import argparse
import copy
import json
import hashlib
import os
import sys
from xml.etree import ElementTree
import requests
import urllib.request
from pathlib import Path
from license_expression import get_spdx_licensing, ExpressionError

if sys.platform.startswith("win"):
    from win32api import GetFileVersionInfo, LOWORD, HIWORD


__version__ = "0.9"
__author__ = "MAB"


def HashFile(filename: str) -> tuple[str, str]:
    """Hashes a file with SHA-256 and SHA-512"""
    sha256 = hashlib.sha256()
    sha512 = hashlib.sha512()
    with open(filename, "rb") as f:
        while True:
            buf = f.read(4096)
            if not buf:
                break
            sha256.update(buf)
            sha512.update(buf)
    return (sha256.hexdigest(), sha512.hexdigest())


class EnrichmentDataBaseComponent:
    """Describes a single component"""

    bom_ref: str = ""
    """
        ID of the component in the SBOM,
        this is matched with the start of the refs in the SBOM
    """
    purl: str = ""
    """PURL of the component"""
    type: str = ""
    """Component type, e.g. 'application', 'framework', 'library', 'firmware', 'file', 'device-driver'... No change if empty string"""
    version: str = ""
    """Component version"""
    creator: str = ""
    """Component e-mail address or website of the creator"""
    filenames = list()
    """Filename of the component"""
    filename_actual = ""
    """A confirmed file name"""
    deployable_hash_sha256 = ""
    """SHA256 hash of the deployable component (executable or library)"""
    deployable_hash_sha512 = ""
    """SHA512 hash of the deployable component (executable or library)"""
    original_licenses = list()
    """Licenses assigned by the creator of the component"""
    distribution_licenses = list()
    """Licenses that can be used by a licensee"""
    effective_license = ""
    """License that is used by the creator of the SBOM"""
    is_executable: bool | None = None
    """Set true to set the executable property (see BSI TR)"""
    is_archive: bool | None = None
    """Set true to set the archive property (see BSI TR)"""
    is_structured: bool | None = None
    """Set true to set the structured property (see BSI TR)"""
    is_assembly: bool | None = None
    """Is this component integrated into parent components (true) or is it an external dependency (false)?"""

    def ParseJSON(self, data: dict):
        if "bom-ref" in data:
            self.bom_ref = data["bom-ref"]
        if "purl" in data:
            self.purl = data["purl"]
        if len(self.bom_ref) == 0 and len(self.purl) == 0:
            print("Missing bom-ref and PURL in component definition")
            exit(-1)

        if "type" in data:
            self.type = data["type"]
        if "version" in data:
            self.version = data["version"]
        if "creator" in data:
            self.creator = data["creator"]
        if "filename" in data:
            if type(data["filename"]) is str:
                self.filenames = [data["filename"]]
            elif type(data["filename"]) is list:
                self.filenames = data["filename"]
        
        if "original_licenses" in data:
            self.original_licenses = data["original_licenses"]
        if "distribution_licenses" in data:
            self.distribution_licenses = data["distribution_licenses"]
        if "effective_license" in data:
            self.effective_license = data["effective_license"]

        if "executable" in data:
            self.is_executable = str(data["executable"]).lower() == "true"
        if "archive" in data:
            self.is_archive = str(data["archive"]).lower() == "true"
        if "structured" in data:
            self.is_structured = str(data["structured"]).lower() == "true"

        if "composition" in data:
            if str(data["composition"]).lower() == "assembly":
                self.is_assembly = True
            if str(data["composition"]).lower() == "dependency":
                self.is_assembly = False

    def __str__(self) -> str:
        d = dict()
        d["bom-ref"] = self.bom_ref
        d["purl"] = self.purl
        d["type"] = self.type
        d["version"] = self.version
        d["creator"] = self.creator
        d["filenames"] = self.filenames
        d["filename_actual"] = self.filename_actual
        d["deployable_hash_sha256"] = self.deployable_hash_sha256
        d["deployable_hash_sha512"] = self.deployable_hash_sha512
        d["effective_license"] = self.effective_license
        try:
            d["is_executable"] = self.is_executable
        except AttributeError:
            pass
        try:
            d["is_archive"] = self.is_archive
        except AttributeError:
            pass
        try:
            d["is_structured"] = self.is_structured
        except AttributeError:
            pass
        return d.__str__()

    def GetDepFromNinja(self, dep_name: str, ninja_file: str) -> str:
        """
        Tries to get the file name for the given dependency from the build.ninja file.
        Parameters:
            dep_file: Name of the library to find without .a or .lib
            ninja_file: Path and name of the build.ninja file
        Returns:
            Filename (absolute or relative) or empty string
        """
        if len(ninja_file) == 0:
            return ""

        if Path(ninja_file).exists():
            with open(ninja_file, encoding="utf-8") as f:
                for line in f:
                    if line.startswith("  LINK_LIBRARIES = "):
                        for filepath in line.split():
                            filename = os.path.basename(filepath)
                            if (
                                filename == dep_name
                                or (filename == "lib" + dep_name + ".a")
                                or (filename == "lib" + dep_name + ".so")
                                or (filename == "lib" + dep_name + ".lib")
                                or (filename == dep_name + ".lib")
                                or (filename == dep_name + ".dll")
                                or (filename == dep_name + ".exe")
                            ):
                                return filepath
        else:
            print("ERROR: Ninja file '" + ninja_file + "' does not exist")
        return ""

    def GetHashFromPip(self):
        """Tries to get the file hash from Python pip. This expects that the filename_actual is set to the wheel file name"""
        try:
            if len(self.purl) > 0 and str(self.purl).startswith("pkg:pypi/"):
                print("\tGetting hash from pip package for '" + self.purl + "'...")
                package_name = str(self.purl).split("/")[1].split("@")[0]
                if len(self.filename_actual) > 0 and self.filename_actual.endswith(
                    ".whl"
                ):
                    package = requests.get(
                        f"https://pypi.org/pypi/{package_name}/json"
                    ).json()
                    for releases in package["releases"].values():
                        for r in releases:
                            if (
                                "filename" in r
                                and r["filename"] == self.filename_actual
                                and "url" in r
                                and len(r["url"]) > 0
                            ):
                                url = r["url"]
                                tmpfn = "temporary"
                                print(
                                    "\tDownloading file '"
                                    + url
                                    + "' as '"
                                    + tmpfn
                                    + "' for '"
                                    + self.bom_ref
                                    + "' for hashing..."
                                )
                                urllib.request.urlretrieve(url, tmpfn)
                                (hash256, hash512) = HashFile(tmpfn)
                                self.deployable_hash_sha256 = hash256
                                self.deployable_hash_sha512 = hash512
                                print("Deleting temporary file '" + tmpfn + "'...")
                                os.remove(tmpfn)
                                return
        except Exception as e:
            print(
                "ERROR: Could not get hash from pip for '"
                + self.bom_ref
                + "': "
                + str(e)
            )

    def FindActualFileName(self):
        """Tries to find the actual file name"""
        if len(self.filename_actual) > 0:
            return

        # If not, check whether the ninja file exists and contains the given file
        ninja_file = cmake_build_dir + "/build.ninja"

        for dep_file in self.filenames:
            # Check whether the file exists
            if Path(dep_file).exists():
                self.filename_actual = dep_file
                break

            if Path(ninja_file).exists():
                file = self.GetDepFromNinja(dep_file, ninja_file)
                if len(file) > 0:
                    if Path(file).exists():
                        self.filename_actual = file
                        break
                    else:
                        print("ERROR: File '" + file + "' from ninja does not exist")

    def CalculateHash(self):
        """Calculates the if the file name is given"""
        self.FindActualFileName()

        if len(self.filename_actual) > 0:
            print("\tHashing file '" + self.filename_actual + "'...")
            (hash256, hash512) = HashFile(self.filename_actual)
            self.deployable_hash_sha256 = hash256
            self.deployable_hash_sha512 = hash512
        elif len(self.filenames) == 1 and len(self.filenames[0]) == 0:
            id = self.bom_ref
            if len(id) == 0:
                id = self.purl
            print(
                "\tWARNING: No filename given or found for '"
                + id
                + "'"
            )
        elif len(self.filenames) > 0:
            id = self.bom_ref
            if len(id) == 0:
                id = self.purl
            print(
                "\tWARNING: Could not generate file hash for '"
                + id
                + "', no file name matched for '"
                + str(self.filenames)
                + "'"
            )

    def _SetStaticLinked(self):
        if self.is_executable is None:
            self.is_executable = True
        if self.is_archive is None:
            self.is_archive = False
        if self.is_structured is None:
            self.is_structured = False
        if self.is_assembly is None:
            self.is_assembly = True

    def _SetDynamicLinked(self):
        if self.is_executable is None:
            self.is_executable = True
        if self.is_archive is None:
            self.is_archive = False
        if self.is_structured is None:
            self.is_structured = False
        if self.is_assembly is None:
            self.is_assembly = False

    def _SetExecutable(self):
        self._SetDynamicLinked()

    def _SetDataArchive(self):
        if self.is_executable is None:
            self.is_executable = False
        if self.is_archive is None:
            self.is_archive = True
        if self.is_structured is None:
            self.is_structured = True
        if self.is_assembly is None:
            self.is_assembly = False

    def AutoDetectAttributes(self):
        """Tries to automatically detect attributes"""
        self.FindActualFileName()

        if len(self.filename_actual) > 0:
            file_ext = Path(self.filename_actual).suffix
            match file_ext:
                case ".a":
                    self._SetStaticLinked()
                case ".lib":
                    self._SetStaticLinked()
                case ".so":
                    self._SetDynamicLinked()
                case ".dll":
                    self._SetDynamicLinked()
                case ".exe":
                    self._SetExecutable()
                case ".zip":
                    self._SetDataArchive()
                case ".gz":
                    self._SetDataArchive()
                case ".bz2":
                    self._SetDataArchive()


class EnrichtmentDataBase:
    """Describes the entries of the enrichment database"""

    components = list()
    """Enrichtment data for components"""
    remove_components = list()
    """List of components to remove"""

    def ReadFromFile(self, filename: str):
        print("Reading enrichment database from '" + filename + "'...")
        with open(filename, encoding="utf-8") as f:
            enrichment_json = json.load(f)
            if "components" in enrichment_json and type(enrichment_json) is dict:
                if type(enrichment_json["components"]) is list:
                    for component in enrichment_json["components"]:
                        edbCompo = EnrichmentDataBaseComponent()
                        edbCompo.ParseJSON(component)

                        self.components.append(edbCompo)

                        # Debug printing the read data
                        # print(edbCompo.__str__())

                if (
                    "remove-components" in enrichment_json
                    and type(enrichment_json["remove-components"]) is list
                ):
                    for component in enrichment_json["remove-components"]:
                        if type(component) is str and len(component) > 0:
                            self.remove_components.append(component)

    def AutoDetectAttributes(self):
        """Tries to automatically detect attributes"""
        print("Detecting attributes...")
        for component in self.components:
            component.AutoDetectAttributes()

    def GetComponent(self, bom_ref: str) -> EnrichmentDataBaseComponent | None:
        """
        Gets a component from the data base. bom-refs are prefix-matched, the first found entry is returned
        Parameters:
            bom_ref: bom-ref to match
        """
        for c in self.components:
            if len(c.bom_ref) > 0 and c.bom_ref.startswith(bom_ref):
                return c
        return None

    def GetComponentEnrichment(self, bom_ref: str, purl: str) -> EnrichmentDataBaseComponent | None:
        """
        Gets a component from the database. bom-ref is checked first for prefix match or exact match (if the components bom-ref ends with '@'). If no bom-ref matches the purl is checked in the same way.
        Parameters:
            bom_ref: bom-ref to match
            purl: purl to match, if no bom-ref matches
        """
        best_match = None

        if len(bom_ref) > 0:
            for c in self.components:
                if len(c.bom_ref) > 0:
                    # Prefix match
                    if bom_ref.startswith(c.bom_ref):
                        if best_match is None or len(best_match.bom_ref) < len(c.bom_ref):
                            best_match = c
                    # Sometimes the SBOM contains a bom-ref without additional data ('@...')...
                    if c.bom_ref.endswith('@') and bom_ref == c.bom_ref[:-1]:
                        if best_match is None or len(best_match.bom_ref) < len(c.bom_ref):
                            best_match = c
            if best_match is not None:
                return best_match

        if len(purl) > 0:
            for c in self.components:
                if len(c.purl) > 0:
                    # Prefix match
                    if purl.startswith(c.purl):
                        if best_match is None or len(best_match.purl) < len(c.purl):
                            best_match = c
                    # Sometimes the SBOM contains a PURL without additional data ('@...')...
                    if c.purl.endswith('@') and purl == c.purl[:-1]:
                        if best_match is None or len(best_match.purl) < len(c.purl):
                            best_match = c
            if best_match is not None:
                return best_match

        # No component data found
        return None

    def Insert(self, comp: EnrichmentDataBaseComponent):
        """Inserts or replaces a component"""
        c = self.GetComponentEnrichment(comp.bom_ref, comp.purl)
        if c is not None:
            self.components.remove(c)
        self.components.append(comp)

    def __str__(self) -> str:
        s = "Component enrichment data:\n"
        for c in self.components:
            s += str(c) + "\n"
            #s += "bom-ref: '" + c.bom_ref + "', purl: '" + c.purl + "'\n"
        s += "Components to remove:"
        for c in self.remove_components:
            s += str(c) + "\n"
        return s


def GetDLLVersion(filename: str) -> str:
    """Gets the version of a Windows DLL, returns an empty string on error"""
    if not Path(filename).exists():
        return ""

    if sys.platform.startswith("win"):
        info = GetFileVersionInfo(filename, "\\")
        ms = info['FileVersionMS']
        ls = info['FileVersionLS']

        versionstr = str(HIWORD(ms)) + "." + str(LOWORD(ms)) + "." + str(HIWORD(ls)) + "." + str(LOWORD(ls))
        return versionstr
    else:
        print("ERROR: GetDLLVersion() is not supported on this platform!")
        exit(-1)


def GetDataFromMSPackagesLockJSON(packages_file: str) -> dict:
    """
    Gets package info from packages.lock.json
    Parameters:
        packages_file: path to packages file
    Returns:
        dictionary of component name to version, filename is implicitly defined as <component name>.dll
    """
    print("Reading package data from '" + packages_file + "'...")
    packages_data = dict()

    if Path(packages_file).exists():
        with open(packages_file, encoding="utf-8") as f:
            packages_json = json.load(f)
            if "dependencies" in packages_json:
                dependencies = packages_json["dependencies"]
                for fw in dependencies:
                    fw_dependencies = dependencies[fw]
                    for dependency_name in fw_dependencies:
                        fw_dependency = fw_dependencies[dependency_name]
                        if "resolved" in fw_dependency:
                            dependency_version = fw_dependency["resolved"]
                            packages_data[dependency_name] = dependency_version
                            print("\tFound '" + dependency_name + "' version '" + dependency_version + "' in lockfile")
    return packages_data


def AddDataFromMSProj(name: str, version: str, path: str, net_framework_version: str, lockfile_data: dict):
    """
    Adds and updates database entries from a MSProj file
    Parameters:
        name: component name
        version: component version, optional
        path: component file, optional
        net_framework_version: .NET Framework version
        lockfile_data: lockfile data
    """
    # Try to guess the path
    if len(path) == 0:
        guess_paths = ["C:/Program Files (x86)/Reference Assemblies/Microsoft/Framework/.NETFramework/" + net_framework_version + "/" + name + ".dll",
                       "C:/Program Files/Reference Assemblies/Microsoft/Framework/.NETFramework/" + net_framework_version + "/" + name + ".dll",
                       "C:/Program Files (x86)/Reference Assemblies/Microsoft/Framework/.NETFramework/" + net_framework_version + "/Facades/" + name + ".dll",
                       "C:/Program Files/Reference Assemblies/Microsoft/Framework/.NETFramework/" + net_framework_version + "/Facades/" + name + ".dll"]

        # Try to guess non-trivial path from lockfile data, e.g. C:\Users\<User>\.nuget\packages\system.valuetuple\4.6.2\lib\net47\System.ValueTuple.dll
        # TODO: this may not pick the correct file if there are multiple files for different .NET versions
        if name in lockfile_data:
            tmp_path = os.path.expanduser("~/.nuget/packages/" + name.lower() + "/" + lockfile_data[name] + "/lib")
            if Path(tmp_path).exists():
                for tmp_dir in os.scandir(tmp_path):
                    if tmp_dir.is_dir():
                        guess_paths.append(tmp_dir.path + "/" + name + ".dll")

        for guess_path in guess_paths:
            if Path(guess_path).exists():
                path = guess_path
                break
        if len(path) == 0:
            print("\tWARNING: Could not guess path for '" + name + "'")

    # Try to get version from file
    if len(version) == 0 and len(path) > 0:
        if Path(path).exists():
            version = GetDLLVersion(path)
        else:
            print("\tWARNING: Could not get info from file '" + path + "': does not exist")

    # Apply changes
    if len(name) > 0 and (len(version) > 0 or len(path) > 0):
        # TODO: Currently this assumes that the bom-ref is equal to the PURL
        bom_ref = "pkg:nuget/" + name + "@"
        comp = edb.GetComponentEnrichment(bom_ref, bom_ref)
        if comp is not None:
            # Component exists already: update entry
            if len(version) > 0:
                print("\tUpdating version of '" + bom_ref + "' to '" + version + "'")
                comp.version = version
            if len(path) > 0:
                print("\tUpdating filename of '" + bom_ref + "' to '" + path + "'")
                comp.filenames = [path]
                comp.filename_actual = path
        else:
            # Component does not exist yet: create entry
            comp = EnrichmentDataBaseComponent()
            comp.bom_ref = bom_ref
            comp.purl = bom_ref
            if len(version) > 0:
                print("\tUpdating version of '" + bom_ref + "' to '" + version + "'")
                comp.version = version
            if len(path) > 0:
                print("\tUpdating filename of '" + bom_ref + "' to '" + path + "'")
                comp.filenames = [path]
                comp.filename_actual = path
        edb.Insert(comp)


def GetDataFromMSProj(edb: EnrichtmentDataBase, project_file: str):
    """
    Tries to get enrichment data from a MSProj C#/.NET project.
    This data is added to existing database entries or new entries are added.
    Parameters:
        edb: Enrichment database
        project_file: Path to .csproj file
    """
    if len(project_file) == 0 or not Path(project_file).exists():
        return

    print("Reading enrichment data from MSProj file '" + project_file + "'")

    project_dir = str(Path(project_file).parent)

    lockfile_data = dict()
    lock_file = project_dir + "/packages.lock.json"
    if Path(lock_file).exists():
        lockfile_data = GetDataFromMSPackagesLockJSON(lock_file)

    xml_tree = ElementTree.parse(project_file)
    # <Project>
    xml_project = xml_tree.getroot()

    # Get .NET Framework version
    net_framework_version = ""
    pgs = xml_project.findall("{http://schemas.microsoft.com/developer/msbuild/2003}PropertyGroup")
    for pg in pgs:
        tfv = pg.findall("{http://schemas.microsoft.com/developer/msbuild/2003}TargetFrameworkVersion")
        if len(tfv) > 0:
            net_framework_version = str(tfv[0].text)
            break

    if len(net_framework_version) > 0:
        print("\t.NET Framework version '" + net_framework_version + "' found")
    else:
        print("\tWARNING: .NET Framework version not found")

    # Get dependencies from lockfile
    print("\tUpdating from lock file...")
    for dep in lockfile_data:
        name = dep
        AddDataFromMSProj(name, "", "", net_framework_version, lockfile_data)

    # Get dependencies from project file
    print("\tUpdating from project file...")
    igs = xml_project.findall("{http://schemas.microsoft.com/developer/msbuild/2003}ItemGroup")
    for ig in igs:
        references = ig.findall("{http://schemas.microsoft.com/developer/msbuild/2003}Reference")
        package_references = ig.findall("{http://schemas.microsoft.com/developer/msbuild/2003}PackageReference")

        for ref in references:
            if "Include" not in ref.attrib:
                continue
            name = ref.attrib["Include"]
            version = ""
            path = ""
            if "Version" in ref.attrib:
                version = ref.attrib["Version"]
            hint_path = ref.find("{http://schemas.microsoft.com/developer/msbuild/2003}HintPath")
            if hint_path is not None:
                if Path(str(hint_path.text)).exists():
                    path = str(hint_path.text)
                else:
                    local_path = project_dir + "/" + str(hint_path.text)
                    if Path(local_path).exists():
                        path = local_path

            AddDataFromMSProj(name, version, path, net_framework_version, lockfile_data)

        for ref in package_references:
            if "Include" not in ref.attrib:
                continue
            name = ref.attrib["Include"]
            version = ""
            version_el = ref.find("{http://schemas.microsoft.com/developer/msbuild/2003}Version")
            if version_el is not None:
                version = str(version_el.text)

            AddDataFromMSProj(name, version, "", net_framework_version, lockfile_data)


def IsKnownLicense(id: str) -> bool:
    """Checks whether the license is a known SPDX license"""
    licensing = get_spdx_licensing()
    try:
        licensing.parse(id, validate=True)
    except ExpressionError:
        return False
    return True


def EnrichComponentLicenses(component: dict, original_licenses: list, distribution_licenses: list, effective_license: str):
    """
    Inserts and updates licensing info. If no license is given but any licensing info found in the SBOM is used.
    Parameters:
        component: SBOM component to update
        original_licenses: List of original licenses, as defined by the manufacturer or empty list
        distribution_licenses: Distribution licenses, these are the applicable licenses or empty list
        effective_license: The actually used license or empty string
    """
    # Step 1: Original Licenses
    # Step 1a: Get original licenses from the database
    # Step 1b: If no original licenses are defined in the database get the original licenses from SBOM
    if len(original_licenses) == 0:
        original_licenses = []
        for li in component["licenses"]:
            if "license" in li:
                li = li["license"]
            if "acknowledgement" in li and li["acknowledgement"] != "declared":
                continue

            if "id" in li:
                original_licenses.append(li["id"])
            elif "name" in li:
                original_licenses.append(li["name"])
            elif "expression" in li:
                original_licenses.append(li["expression"])

    # Step 1c: apply later

    # Step 2: Distribution Licenses
    # Step 2a: Get distribution licenses from database
    # Step 2b: If no distribution licenses are found, get them from the SBOM
    if len(distribution_licenses) == 0:
        distribution_licenses = []
        for li in component["licenses"]:
            if "license" in li:
                li = li["license"]
            if "acknowledgement" in li and li["acknowledgement"] != "concluded":
                continue

            if "id" in li:
                distribution_licenses.append(li["id"])
            elif "name" in li:
                distribution_licenses.append(li["name"])
            elif "expression" in li:
                distribution_licenses.append(li["expression"])

    # Step 2c: If still no distribution licenses are found, use the original licenses
    if len(distribution_licenses) == 0:
        distribution_licenses = original_licenses

    # Step 1c/2d: Remove all licenses from SBOM
    component["licenses"] = []

    # Step 1c: Replace all original licenses in the SBOM
    if len(original_licenses) > 0:
        for license in original_licenses:
            if IsKnownLicense(license):
                print("\tAdding known original license '" + license + "'...")
                component["licenses"].append(
                    # {"license": {"id": license, "acknowledgement": "declared"}}
                    {
                        "id": license,
                        "expression": license,
                        "acknowledgement": "declared",
                    }
                )
            else:
                print("\tAdding original license '" + license + "'...")
                component["licenses"].append(
                    # {"license": {"name": license, "acknowledgement": "declared"}}
                    {
                        "name": license,
                        "expression": license,
                        "acknowledgement": "declared",
                    }
                )

    # Step 2d: Replace all distribution licenses in the SBOM
    if len(distribution_licenses) > 0:
        for license in distribution_licenses:
            if IsKnownLicense(license):
                print(
                    "\tAdding known distribution license '" + license + "'..."
                )
                component["licenses"].append(
                    # {"license": {"id": license, "acknowledgement": "concluded"}}
                    {
                        "id": license,
                        "expression": license,
                        "acknowledgement": "concluded",
                    }
                )
            else:
                print("\tAdding distribution license '" + license + "'...")
                component["licenses"].append(
                    # {"license": {"name": license, "acknowledgement": "concluded"}}
                    {
                        "name": license,
                        "expression": license,
                        "acknowledgement": "concluded",
                    }
                )

    # Step 3: Effective License
    # Step 3a: Get effective license from database
    # Step 3b: If the effective license is not defined in the database try to get it from the SBOM
    for prop in component["properties"]:
        if "name" in prop and prop["name"] == "bsi:component:effectiveLicense":
            effective_license = prop["value"]
            break
    # Step 3c: If the effective license is still not defined take the single distribution license
    if len(effective_license) == 0 and len(distribution_licenses) == 1:
        effective_license = distribution_licenses[0]

    # Remove effective license entry from SBOM
    for prop in component["properties"]:
        if "name" in prop and prop["name"] == "bsi:component:effectiveLicense":
            component["properties"].remove(prop)
            break

    # Insert effective license
    if len(effective_license) > 0:
        print(
            "\tAdding effective license '"
            + effective_license
            + "'..."
        )
        licenseData = {
            "name": "bsi:component:effectiveLicense",
            "value": effective_license,
        }
        component["properties"].append(licenseData)


def EnrichComponent(edb: EnrichtmentDataBase, component: dict):
    """
    Enriches a SBOM component
    Parameters:
        edb: Enrichment data base
        component: SBOM component object
    """
    bom_ref = component["bom-ref"]

    bom_ref = ""
    purl = ""
    if "bom-ref" in component:
        bom_ref = component["bom-ref"]
    if "purl" in component:
        purl = component["purl"]
    enrich_component = edb.GetComponentEnrichment(bom_ref, purl)

    if enrich_component is not None:    
        print("Enriching component '" + bom_ref + "'...")

        # Fill missing info from SBOM
        if len(enrich_component.purl) == 0 and "purl" in component:
            enrich_component.purl = component["purl"]

        # Create structure
        if "properties" not in component:
            component["properties"] = list()
        if "externalReferences" not in component:
            component["externalReferences"] = list()
        if "licenses" not in component:
            component["licenses"] = list()
        if "properties" not in component:
            component["properties"] = list()

        # Type
        if len(enrich_component.type) > 0:
            print("\tSetting component type to '" + enrich_component.type + "'")
            component["type"] = enrich_component.type

        # Version
        if len(enrich_component.version) > 0:
            print("\tSetting component version to '" + enrich_component.version + "'")
            component["version"] = enrich_component.version

        # Creator
        if len(enrich_component.creator) > 0:
            print(
                "\tAdding manufacturer contact: '"
                + enrich_component.creator
                + "'..."
            )
            if "manufacturer" not in component:
                component["manufacturer"] = dict()
            if "@" in enrich_component.creator:
                if "contact" not in component["manufacturer"]:
                    component["manufacturer"]["contact"] = list()
                component["manufacturer"]["contact"].append(
                    {"email": enrich_component.creator}
                )
            else:
                component["manufacturer"]["url"] = [enrich_component.creator]

            # sbomqs reads the manufacturer info from "supplier" instead of "manufacturer"
            print(
                "\tAdding supplier contact to: '"
                + enrich_component.creator
                + "'..."
            )
            if "supplier" not in component:
                component["supplier"] = dict()
            if "@" in enrich_component.creator:
                if "contact" not in component["supplier"]:
                    component["supplier"]["contact"] = list()
                component["supplier"]["contact"].append(
                    {"email": enrich_component.creator}
                )
            else:
                component["supplier"]["url"] = [enrich_component.creator]

        # Licensing
        EnrichComponentLicenses(component, enrich_component.original_licenses, enrich_component.distribution_licenses, enrich_component.effective_license)

        # Filename of the component
        if len(enrich_component.filename_actual) > 0:
            filename = os.path.basename(enrich_component.filename_actual)
            has_filename = False
            for p in component["properties"]:
                if "name" in p and p["name"] == "bsi:component:filename":
                    has_filename = True
            if not has_filename:
                print("\tAdding filename '" + filename + "'...")
                filenameData = {"name": "bsi:component:filename", "value": filename}
                component["properties"].append(filenameData)
        else:
            # Get filename from SBOM
            for p in component["properties"]:
                if "name" in p and p["name"] == "bsi:component:filename":
                    enrich_component.filename_actual = p["value"]
                    print(
                        "Found filename for '"
                        + enrich_component.bom_ref
                        + "' in SBOM: '"
                        + enrich_component.filename_actual
                        + "'"
                    )
                    break

        if len(enrich_component.filename_actual) > 0:
            if len(enrich_component.deployable_hash_sha512) == 0:
                enrich_component.CalculateHash()

            # For Python projects: Try to get the hash for the wheel file
            if len(enrich_component.deployable_hash_sha512) == 0:
                enrich_component.GetHashFromPip()

            # Hash value of the deployable component
            if len(enrich_component.deployable_hash_sha512) > 0:
                print(
                    "\tAdding deployable hash of file '"
                    + enrich_component.filename_actual
                    + "'..."
                )
                filename = os.path.basename(enrich_component.filename_actual)
                uri = "file://" + filename
                hashData_sha256 = {
                    "alg": "SHA-256",
                    "content": enrich_component.deployable_hash_sha256,
                }
                hashData_sha512 = {
                    "alg": "SHA-512",
                    "content": enrich_component.deployable_hash_sha512,
                }
                hashData = {
                    "url": uri,
                    "type": "distribution",
                    "hashes": [hashData_sha256, hashData_sha512],
                }
                component["externalReferences"].append(hashData)

                # Clear / init hashes list - wrong place according to the BSI but sbomqs expects it here and in SHA-256 format
                component["hashes"] = list()
                component["hashes"].append(hashData_sha256)
                component["hashes"].append(hashData_sha512)

        # Set executable property
        try:
            print(
                "\tSetting '"
                + enrich_component.bom_ref
                + "' executable property..."
            )
            if enrich_component.is_executable is True:
                component["properties"].append(
                    {"name": "bsi:component:executable", "value": "executable"}
                )
            else:
                component["properties"].append(
                    {"name": "bsi:component:executable", "value": "non-executable"}
                )
        except AttributeError:
            pass

        # Set archive property
        try:
            print(
                "\tSetting '" + enrich_component.bom_ref + "' archive property..."
            )
            if enrich_component.is_archive is True:
                component["properties"].append(
                    {"name": "bsi:component:archive", "value": "archive"}
                )
            else:
                component["properties"].append(
                    {"name": "bsi:component:archive", "value": "no archive"}
                )
        except AttributeError:
            pass

        # Set structured property
        try:
            print(
                "\tSetting '"
                + enrich_component.bom_ref
                + "' structured property..."
            )
            if enrich_component.is_structured is True:
                component["properties"].append(
                    {"name": "bsi:component:structured", "value": "structured"}
                )
            else:
                component["properties"].append(
                    {"name": "bsi:component:structured", "value": "unstructured"}
                )
        except AttributeError:
            pass

    else:
        print("WARNING: No enrichment data found for component '" + bom_ref + "'")
        # Update license info by data contained in the sBOM
        EnrichComponentLicenses(component, list(), list(), "")


def FindBomRefsForPURL(edb: EnrichtmentDataBase, sbom_json: dict):
    """Gets the bom-refs via the PURL if the bom-ref is not defined in the enrichment file"""
    print("Matching PURLs to bom-refs...")

    # Wildcards will be removed later
    wildcards = list()

    for edbcomp in edb.components:
        # if the bom-ref is not set but a PURL
        if len(edbcomp.bom_ref) == 0 and len(edbcomp.purl) > 0:
            wildcard = False
            exact = ""
            if str.endswith(edbcomp.purl, "*"):
                # wildcard match: inserts the same data into multiple similarly named components
                wildcard = True
                purl = edbcomp.purl[:-1]
            elif str.endswith(edbcomp.purl, "@"):
                # any version match: matches by the exact purl before the '@', but also prefix match
                exact = edbcomp.purl[:-1]
                purl = edbcomp.purl
            else:
                # any other prefix match
                purl = edbcomp.purl

            # update database entry or create new ones
            if "components" in sbom_json:
                for component in sbom_json["components"]:
                    if (
                        "bom-ref" in component
                        and "purl" in component
                        and (component["purl"].startswith(purl)
                             or (len(exact) > 0 and component["purl"] == exact))
                    ):
                        if wildcard:
                            # prüfen, ob es zu der bom-ref schon einen Eintrag gibt
                            exists = False
                            for edbcomp2 in edb.components:
                                if edbcomp2.bom_ref == component["bom-ref"]:
                                    exists = True
                                    break
                            if not exists:
                                print(
                                    "\tFound bom-ref '"
                                    + component["bom-ref"]
                                    + "' for purl '"
                                    + edbcomp.purl
                                    + "', duplicating entry..."
                                )
                                new_entry = copy.deepcopy(edbcomp)
                                new_entry.bom_ref = component["bom-ref"]
                                new_entry.purl = component["bom-ref"]
                                edb.components.append(new_entry)
                        else:
                            print(
                                "\tFound bom-ref '"
                                + component["bom-ref"]
                                + "' for purl '"
                                + edbcomp.purl
                                + "', updating entry..."
                            )
                            edbcomp.bom_ref = component["bom-ref"]
                            break

            # do the same for the SBOM's main component
            if "metadata" in sbom_json and "component" in sbom_json["metadata"]:
                component = sbom_json["metadata"]["component"]
                if (
                    "bom-ref" in component
                    and "purl" in component
                    and (component["purl"].startswith(purl)
                         or (len(exact) > 0 and component["purl"] == exact))
                ):
                    if wildcard:
                        # prüfen, ob es zu der bom-ref schon einen Eintrag gibt
                        exists = False
                        for edbcomp2 in edb.components:
                            if edbcomp2.bom_ref == component["bom-ref"]:
                                exists = True
                        if not exists:
                            print(
                                "\tFound bom-ref '"
                                + component["bom-ref"]
                                + "' for purl '"
                                + edbcomp.purl
                                + "', duplicating entry..."
                            )
                            new_entry = copy.deepcopy(edbcomp)
                            new_entry.bom_ref = component["bom-ref"]
                            edb.components.append(new_entry)
                    else:
                        print(
                            "\tFound bom-ref '"
                            + component["bom-ref"]
                            + "' for purl '"
                            + edbcomp.purl
                            + "', updating entry..."
                        )
                        edbcomp.bom_ref = component["bom-ref"]

    # Remove wildcard entries
    for wc in wildcards:
        edb.components.remove(wc)


def RemoveComponents(components: list):
    """
    Removes the given components from the SBOM
    Parameters:
        components: List of bom-ref prefixes
    """
    if "components" not in sbom_json:
        print("WARNING: No components in SBOM!")
        return

    for bom_ref_prefix in components:
        bom_ref = ""

        for component in sbom_json["components"]:
            if component["bom-ref"].startswith(bom_ref_prefix):
                # Get bom-ref from components list
                bom_ref = component["bom-ref"]

                # Remove from components list
                print("Removing component '" + bom_ref + "'...")
                sbom_json["components"].remove(component)

        # if bom-ref was not found: try purl
        for component in sbom_json["components"]:
            if component["purl"].startswith(bom_ref_prefix):
                # Get bom-ref from components list
                bom_ref = component["bom-ref"]

                # Remove from components list
                print("Removing component '" + bom_ref + " (purl '" + component["purl"] + "')'...")
                sbom_json["components"].remove(component)

        if len(bom_ref) > 0:
            for dep in sbom_json["dependencies"]:
                # Own entry
                if dep["ref"] == bom_ref:
                    # Remove own dependencies entry
                    print("Removing dependencies of '" + bom_ref + "'...")
                    sbom_json["dependencies"].remove(dep)

            # Other dependency entries
            for dep in sbom_json["dependencies"]:
                # Remove from dependencies of other components
                if "dependsOn" in dep and bom_ref in dep["dependsOn"]:
                    print(
                        "Removing dependency to '"
                        + bom_ref
                        + "' from '"
                        + dep["ref"]
                        + "'..."
                    )
                    dep["dependsOn"].remove(bom_ref)

        # else:
            # print(
            #     "WARNING: Could not remove component, bom-ref prefix '"
            #     + bom_ref_prefix
            #     + "' not found"
            # )


def RemoveOrphans(sbom_json: dict):
    """Removes all orphan components"""
    if "components" not in sbom_json:
        print("WARNING: No components in SBOM!")
        return

    orphans = []
    while True:
        # First add all components...
        for c in sbom_json["components"]:
            orphans.append(c["bom-ref"])
        # ...then remove all that are depended on from the list
        for d in sbom_json["dependencies"]:
            if "dependsOn" in d:
                for do in d["dependsOn"]:
                    if do in orphans:
                        orphans.remove(do)
        # also remove the main component
        main_component = sbom_json["metadata"]["component"]["bom-ref"]
        if main_component in orphans:
            orphans.remove(main_component)

        # Remove orphans
        if len(orphans) > 0:
            print("Removing orphan components: " + str(orphans))
            RemoveComponents(orphans)
        else:
            break

        orphans = []


###############################################################################
# Script execution start
###############################################################################


cmake_build_dir = ""
"""Name of the CMake build directory, may be empty"""
enrichment_file = ""
"""The enrichment data file, must be in JSON format"""
sbom_file_in = ""
"""The SBOM input file, must be in CycloneDX JSON format"""
sbom_file_out = ""
"""The SBOM output file, must be in CycloneDX JSON format"""
msbuild_proj = ""
"""MSProject file, for C#/.NET projects"""

argparser = argparse.ArgumentParser(
    description="Commonplace Robotics GmbH SBOM enrichment tool v" + __version__
)
argparser.add_argument("enrichtment_file", type=str, help="Enrichment data file")
argparser.add_argument("sbom_in", type=str, help="SBOM input file")
argparser.add_argument("-o", "--out", type=str, help="SBOM output file")
argparser.add_argument("-b", "--cmake_dir", type=str, help="CMake build directory")
argparser.add_argument("-m", "--msbuild_proj", type=str, help="MSBuild project file")
args = argparser.parse_args()

print("Commonplace Robotics GmbH SBOM enrichment tool v" + __version__)

if type(args.enrichtment_file) is str:
    enrichment_file = args.enrichtment_file
if type(args.sbom_in) is str:
    sbom_file_in = sbom_file_out = args.sbom_in
if type(args.out) is str:
    sbom_file_out = args.out
if type(args.cmake_dir) is str:
    cmake_build_dir = args.cmake_dir
if type(args.msbuild_proj) is str:
    msbuild_proj = args.msbuild_proj

###############################################################################
# Validate arguments
###############################################################################
if len(cmake_build_dir) > 0 and not Path(cmake_build_dir).exists():
    print("Error: CMake build directory given but it does not exist")
    exit(-1)

if len(enrichment_file) == 0:
    print("Error: Enrichment file not given")
    exit(-1)

if len(sbom_file_in) == 0:
    print("Error: SBOM input file not given")
    exit(-1)

if len(sbom_file_out) == 0:
    print("Error: SBOM output file not given")
    exit(-1)

if not Path(enrichment_file).exists():
    print("Error: Enrichment file '" + enrichment_file + "' does not exist")
    exit(-1)

if not Path(sbom_file_in).exists():
    print("Error: SBOM input file '" + sbom_file_in + "' does not exist")
    exit(-1)

###############################################################################
# Read enrichment file
###############################################################################
edb = EnrichtmentDataBase()
edb.ReadFromFile(enrichment_file)

###############################################################################
# Read SBOM
###############################################################################
print("Reading SBOM from '" + sbom_file_in + "'...")
with open(sbom_file_in, encoding="utf-8") as f:
    sbom_json = json.load(f)

###############################################################################
# Get bom-refs from PURL
###############################################################################
FindBomRefsForPURL(edb, sbom_json)

if len(msbuild_proj) > 0:
    GetDataFromMSProj(edb, msbuild_proj)

edb.AutoDetectAttributes()

###############################################################################
# Remove components that are marked for removal in the enrichment data base
###############################################################################
RemoveComponents(edb.remove_components)

###############################################################################
# Find orphan components and also remove them
###############################################################################
RemoveOrphans(sbom_json)

###############################################################################
# Enrich components
###############################################################################
if "components" in sbom_json:
    for component in sbom_json["components"]:
        EnrichComponent(edb, component)

# Enrich target component
if "metadata" in sbom_json and "component" in sbom_json["metadata"]:
    print("Enriching main component...")
    component = sbom_json["metadata"]["component"]
    EnrichComponent(edb, component)
else:
    print("WARNING: Target component not found in SBOM (metadata -> component)")

###############################################################################
# Enrich compositions - describes the completeness of dependencies
###############################################################################
print("Adding compositions...")
main_component_ref = sbom_json["metadata"]["component"]["bom-ref"]
sbom_json["compositions"] = list()
# All components are in the dependencies list, create composition entries for each
for c in sbom_json["dependencies"]:
    # According to BSI the composition must either contain composition XOR assembly
    assemblies = {"ref": c["ref"], "aggregate": "unknown", "assemblies": []}
    dependencies = {"ref": c["ref"], "aggregate": "unknown", "dependencies": []}
    if c["ref"] == main_component_ref:
        # Implicitly mark the main componente complete, since we must describe all direct dependencies according to BSI
        assemblies["aggregate"] = "complete"
        dependencies["aggregate"] = "complete"

    # Add its dependencies to either assembly or dependency
    if "dependsOn" in c:
        for dep in c["dependsOn"]:
            is_assembly = False
            component = edb.GetComponent(dep)
            if component is not None and component.is_assembly is not None:
                is_assembly = component.is_assembly
            if is_assembly:
                assemblies["assemblies"].append(dep)
            else:
                dependencies["dependencies"].append(dep)

    sbom_json["compositions"].append(assemblies)
    sbom_json["compositions"].append(dependencies)

###############################################################################
# Export result
###############################################################################
print("Writing SBOM to '" + sbom_file_out + "'...")
with open(sbom_file_out, "w", encoding="utf-8") as f:
    f.write(json.dumps(sbom_json, indent=2))

print("SBOM enrichment done.")
exit(0)
