# bindy

Python binding для библиотеки **Bindy**.

Репозиторий: https://github.com/EPC-MSU/Bindy

## Установка

Для установки выполните команду:

```bash
python -m pip install bindy
```

## Запуск примера

1. Скопируйте из корня репозитория файл **sample_keyfile.sqlite** и положите в Вашу рабочую папку.

2. Скопируйте из репозитория файл **binding/python/example.py** и положите в Вашу рабочую папку.

3. Запустите сервер:

   ```bash
   python example.py sample_keyfile.sqlite
   ```

4. Запустите клиента:

   ```bash
   python example.py sample_keyfile.sqlite localhost HelloWorld
   ```

