# libbindy

Python binding для библиотеки **Bindy**.

## Сборка wheel

1. Укажите корректную версию **libbindy** в полу **version** в файле **setup.py**.

2. Соберите библиотеку **Bindy** для win32, win64 и debian.

3. Собранные библиотеки положите в папки **libbindy/libs/win32**, **libbindy/libs/win64**, **libbindy/libs/debian**.

4. Выполните команды:

   ```bash
   python -m pip install wheel
   python setup.py bdist_wheel --universal
   ```

