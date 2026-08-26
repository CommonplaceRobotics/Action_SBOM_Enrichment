# SBOM Enrichment Helper

Der Helper ermöglicht es Informationen in eine SBOM zu injizieren und überflüssige Abhängigkeiten zu entfernen, um die Anforderungen der [BSI-Richtlinie BSI TR-03183](https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TR03183/BSI-TR-03183-2_v2_1_0.pdf?__blob=publicationFile&v=5) zu erfüllen.

Hinweis: Dieses Repository ist öffentlich um die Integration in unsere CI zu vereinfachen. Verwendung durch Dritte geschieht auf eigenes Risiko, siehe [UNLICENSE](UNLICENSE).

## Verwendung

### Manueller Aufruf
Der Ablauf der SBOM-Generierung sieht damit so aus:
1. SBOM erzeugen
2. SBOM automatisiert erweitern (Enrichment + Augmentation, z.B. via sbomify)
3. Fehlende Informationen mit dem Helper einfügen
4. SBOM validieren

Das Skript hat die folgenden Parameter:
```
usage: SbomEnrichment.py [-h] [-o OUT] [-b CMAKE_DIR] enrichtment_file sbom_in

positional arguments:
  enrichtment_file      Enrichment data file
  sbom_in               SBOM input file

options:
  -h, --help            show this help message and exit
  -o, --out OUT         SBOM output file
  -b, --cmake_dir CMAKE_DIR
                        CMake build directory
```

Parameter:
1. ```enrichment_file```: Datei mit den Enrichment-Informationen an, s.u.
2. ```sbom_in```: Eingabe-SBOM-Datei
3. ```out```: Ausgabe-SBOM-Datei, falls nicht angegeben wird die Eingabedatei überschrieben
4. ```cmake_dir```: Pfad zum CMake-Build-Verzeichnis

### Github-Actions
Das Skript kann auch als Github-Action aufgerufen werden. Anforderung dazu ist, dass Python 3 installiert ist.

```yaml
- name: Final SBOM enrichment
  uses: CommonplaceRobotics/Action_SBOM_Enrichment@v1
  with:
	database: .github/workflows/sbom_enrichment_db.json
	sbom: sbom.cdx.json
	sbom_out: sbom_out.cdx.json
	cmake_build_dir: out/build/Linux/armv8_32/Release
```

Parameter:
* database: Enrichment-Datenbank
* sbom: SBOM-Eingabedatei, wird überschrieben, falls sbom_out nicht gesetzt ist
* sbom_out: SBOM-Ausgabedatei (optional)
* cmake_dir: CMake-Build-Verzeichnis (optional)

## Enrichment-Datei
Die Enrichment-Datei ist eine JSON-Datei mit einer eigenen Struktur. Für jede in der SBOM angegebenen Komponente wird geprüft ob diese in der Enrichment-Datei enthalten ist und ggf. mit den dort angegebenen Informationen erweitert.

Struktur:
```json
{
    "components":
    [
        {
            "purl": "pkg:generic/minimal-app-c@",
            "creator": "foomailto:me@cpr.com",
            "filename": "file",
            "effective_license": "my license",
            "original_licenses": ["MIT"],
            "distribution_licenses": ["MIT"],
            "executable": true,
            "archive": false,
            "structured": false
        },
		{
            "bom-ref": "pkg:conan/zlib@",
            "creator": "https://www.zlib.net/",
			"filename": ["zlib", "libz"],
            "composition": "assembly"
        }
    ],
    "remove-components":
    [
        "pkg:conan/cmake@",
        "pkg:conan/gtest@"
    ]
}
```


### components
Einträge im Array ```components``` erweitern die Komponenten in der SBOM um zusätzliche Metadaten. ```bom-ref``` oder ```purl``` müssen angegeben werden, alle anderen Attribute sind optional. Undefinierte Attribute werden nicht in die SBOM eingefügt.

Einträge:
* ```bom-ref```: Anfang der Komponenten-ID in der SBOM. Wenn eine ID in der SBOM mit der hier angegebenen ID anfängt wird die Komponente mit den folgenden Informationen erweitert.
* ```purl```: Kann alternativ zur bom-ref angegeben werden. Hierüber kann auch das eigentliche Target erkannt werden. Der PURL-Eintrag wird mit dem Anfang der PURLs der Komponenten verglichen und die bom-ref der ersten gefundenen Komponente übernommen. Wenn der Eintrag mit einem '*' endet wird der Eintrag für alle gefundenen Komponenten dupliziert, so können z.B. ähnlich benannte Bibliotheken mit einem Eintrag zusammengefasst werden (Achtung bei Angabe eines Dateinamen!).
* ```creator```: E-Mail-Adresse oder Webseite des Autors der Komponente
* ```filename```: Dateiname oder Array alternativer Dateinamen der Binärdatei der Komponente, falls vorhanden. Wenn die Datei nicht lokal gefunden werden kann wird versucht den Pfad aus \<CMake build directory\>/build.ninja zu lesen, dabei werden die Endungen .a, .so, .lib und .exe versucht.
* ```original_licenses```: Die vom Hersteller der Komponente festgelegten Lizenzen.
* ```distribution_licenses```: Die verwendbaren Lizenzen der Komponente.
* ```effective_license```: Die vom Ersteller der SBOM verwendete Lizenz. Dies sollte verwendet werden, falls mehrere Lizenzen zur Verfügung stehen.
* ```executable```: Ist die Komponente ausführbar (inkl. Skripte und Libraries)? Ist relevant zur Erkennung von Schadcode.
* ```archive```: Ist die Komponente ein Archiv, d.h. in seine bestandteile zerteilbar?
* ```structured```: Ist die Komponente strukturiert, d.h. enthält sie Metadaten anhand derer die Bestandteile erkannt werden können?
* ```composition```: Beschreibt, wie die verwendende Komponente(n) diese einbindet.
    * ```assembly``` bedeutet, dass die Komponente Teil der übergeordneten Komponente(n) wird, z.B. bei statischem Linken oder vendored Code.
    * ```dependency``` bedeutet, dass die Komponente eine externe Abhängigkeit (z.B. dynamisches Linken oder Python-Pakete). Dies ist der Standartwert.

Bei C/C++-Projekten mit CMake und Conan werden die folgenden Einträge versucht automatisch zu erkennen, falls sie nicht manuell definiert sind. Dies sollte in der SBOM geprüft und falls die Werte nicht stimmen in die Enrichment-Datei eingetragen werden:
* ```executable```: True, wenn Bibliothek oder ```.exe```
* ```archive```: False, wenn Bibliothek oder ```.exe``` (Achtung bei selbstentpackenden Archiven, Firmware etc.!)
* ```structured```: False, wenn Bibliothek oder ```.exe``` (Achtung bei selbstentpackenden Archiven, Binaries mit integrierte SBOM etc.!)
* ```composition```:
    * ```assembly``` bei ```.a``` oder ```.lib```
    * ```dependency``` bei ```.so```, ```.dll``` oder ```.exe```

Archive (.zip, .gz, .bz2) werden als ```archive```, ```structured``` und ```composition``` = ```dependency``` erkannt.

### remove-components
Einträge in diesem Array definieren Komponenten, die (falls vorhanden) aus der SBOM entfernt werden sollten, bspw. weil es sich um Build- oder Test-Tools handelt. Die Enträge sind ```bom-ref```- oder ```purl```-Präfixe wie oben definiert.
