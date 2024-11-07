# bindy

Python binding для библиотеки **Bindy**.

## Сборка wheel

1. Укажите корректную версию **bindy** в поле **version** в файле **setup.py**.

2. Соберите библиотеки **Bindy** для debian, win32, win64.

3. Собранные библиотеки положите в папки **bindy/debian**, **bindy/win32**, **bindy/win64**.

4. Выполните команды:

   ```bash
   python -m pip install wheel
   python setup.py bdist_wheel --universal
   ```

## Запуск примера

1. Скопируйте из корня репозитория файл **sample_keyfile.sqlite** и положите в папку **binding/python**.

2. Запустите сервер:

   ```bash
   python example.py sample_keyfile.sqlite
   ```

3. Запустите клиента:

   ```bash
   python example.py sample_keyfile.sqlite localhost HelloWorld
   ```

