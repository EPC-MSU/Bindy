from setuptools import find_packages, setup


setup(name="bindy",
      version="2.0.1",
      description="A lightweight cross-platform framework for cloud service",
      url="https://github.com/EPC-MSU/Bindy",
      author="EPC MSU",
      author_email="info@physlab.ru",
      classifiers=["Programming Language :: Python :: 3",
                   "License :: OSI Approved :: MIT License",
                   "Operating System :: OS Independent"],
      license="MIT",
      package_data={"bindy": ["debian/libbindy.so",
                              "win32/bindy.dll",
                              "win64/bindy.dll"]},
      packages=find_packages(),
      python_requires=">=3.6")
