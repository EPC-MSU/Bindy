# bindy

Python binding for the **Bindy** library.

Repository: https://github.com/EPC-MSU/Bindy

## Installation

To install, run the command:

```bash
python -m pip install bindy
```

## Running the example

1. Copy the file **sample_keyfile.sqlite** from the root of the repository and put it in your working folder.

2. Copy the file **binding/python/example.py** from the repository and put it in your working folder.

3. Start the server:

   ```bash
   python example.py sample_keyfile.sqlite
   ```

4. Start the client:

   ```bash
   python example.py sample_keyfile.sqlite localhost HelloWorld
   ```

