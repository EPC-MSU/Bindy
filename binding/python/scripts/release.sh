: "${TWINE_USERNAME:?TWINE_USERNAME empty, exiting}"
: "${TWINE_PASSWORD:?TWINE_PASSWORD empty, exiting}"
cd ..

[ -d "./dist" ] && rm -rf ./dist
[ -d "./src" ] && rm -rf ./src
[ -d "./tests" ] && rm -rf ./tests
[ -d "./build-venv" ] && rm -rf ./build-venv
[ -d "LICENSE" ] && rm LICENSE

mkdir src
cp -R ./bindy ./src/bindy
mkdir tests
cp ../../LICENSE LICENSE

python3 -m venv build-venv
source ./build-venv/bin/activate

python -m pip install --upgrade pip
python -m pip install build
python -m build

python -m pip install twine
python -m twine upload dist/* 
