from setuptools import setup, find_packages

setup(
    name="jsfinder",
    version="1.0.0",
    description="Domain Attack-Surface & Static Resource Discovery Tool",
    long_description=open("README.md", "r", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    author="Tejas Thorat",
    author_email="thorattejas003@gmail.com",
    url="https://github.com/tejassroot/jsfinder",
    packages=find_packages(),
    python_requires=">=3.11",
    install_requires=[
        "httpx>=0.27.0",
        "beautifulsoup4>=4.12.0",
        "dnspython>=2.6.0",
    ],
    entry_points={
        "console_scripts": [
            "jsfinder=jsfinder.cli:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Programming Language :: Python :: 3.14",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
    ],
)
