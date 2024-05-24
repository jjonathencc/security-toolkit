from setuptools import setup, find_packages

setup(
    name="security-toolkit",
    version="0.1",
    author="Jonathen Cuvelier Flores",
    description="A collection of tools for security analysis",
    packages=find_packages(),
    install_requires=[
        'requests~=2.32.2',
        'click~=8.1.7',
        'aiofiles~=23.2.1',
        'aiohttp~=3.9.5',
        'setuptools~=70.0.0',
    ],
    entry_points={
        'console_scripts': [
            'security-toolkit=toolkit.main:main',  # Replace with your CLI entry point
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3.11",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.11',
)
