from setuptools import setup, find_packages

setup(
    name='shadowscan',
    version='1.1',
    description='Offensive OSINT Framework for Recursive Scanning',
    author='Sibasundar Barik',
    packages=find_packages(),
    install_requires=[
        'requests', 'rich', 'pyfiglet', 'easyocr', 
        'spacy', 'exifread', 'textblob', 'thefuzz', 'pillow-heif'
    ],
    entry_points='''
        [console_scripts]
        shadowscan=main:main
    ''',
)