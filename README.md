# QtExtract

QtExtract is a standalone Python tool for extracting Qt resource files embedded in x86/x64 Windows executables and DLLs. It is designed for reverse engineers, malware analysts, and anyone interested in recovering resources (such as images, translations, or UI files) from Qt-based Windows applications.

**Key Features:**
- Extracts Qt resources from compiled Windows binaries (.exe/.dll)
- Supports both 32-bit and 64-bit PE files
- No dependencies: pure Python, no external libraries required
- Fast scanning using signature-based detection of Qt resource registration
- CLI interface for automation and scripting

**Limitations:**
- Only works on Windows PE binaries (not Linux/macOS or other formats)
- May not detect all Qt resource chunks (see notes below)

## Installation

No installation is required. QtExtract is a single Python script with zero dependencies. It works with Python 3.6+ (no external packages needed).

1. Download or clone this repository:
   ```sh
   git clone https://github.com/yourusername/qtextract.git
   cd qtextract
   ```
2. (Optional) Add the directory to your PATH or create a shortcut for easier access.

## Usage

Run the tool directly with Python:

```sh
python -m qtextract filename [options]
```

Where `filename` is the path to a Windows .exe or .dll file built with Qt.

### Options

```
usage: qtextract filename [options]
options:
  --help                   Print this help
  --chunk chunk_id         The chunk to dump. Exclude this to see a list of chunks (if any can be found) and use 0 to dump all chunks
  --output directory       For specifying an output directory
  --scanall                Scan the entire file (instead of the first executable section)
  --section section        For scanning a specific section
  --data, --datarva info   [Advanced] Use these options to manually provide offsets to a qt resource in the binary
                           (e.g. if no chunks were found automatically by qtextract).
                           'info' should use the following format: %x,%x,%x,%d
                           where the first 3 hexadecimal values are offsets to data, names, and tree
                           and the last decimal value is the version (usually 1-3).

                           If '--datarva' is used, provide RVA values (offsets from the image base) instead of file offsets.
                           See check_data_opt() in main.rs for an example on finding these offsets using IDA.
```

### Example

To extract all Qt resources from a Windows executable:

```sh
python -m qtextract myapp.exe
```

To specify an output directory:

```sh
python -m qtextract myapp.exe --output extracted_resources
```

To list available resource chunks and extract a specific one:

```sh
python -m qtextract myapp.exe --chunk 1
```

## Notes
- False positives/negatives are possible due to signature-based detection.
- For advanced manual extraction, see the `--data` and `--datarva` options above.

## License
[BSD 3-Clause License](LICENSE)
