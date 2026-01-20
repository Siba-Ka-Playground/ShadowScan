from setuptools import setup, find_packages

setup(
    name='shadowscan',
    version='1.2',
    description='Offensive OSINT Framework',
    author='Sibasundar Barik',
    # This correctly finds the 'shadowscan_core' folder
    packages=find_packages(),
    install_requires=[
        'requests', 'rich', 'pyfiglet', 'easyocr', 
        'spacy', 'exifread', 'textblob', 'thefuzz', 'pillow-heif'
    ],
    # UPDATED ENTRY POINT: Folder.File:Function
    entry_points='''
        [console_scripts]
        shadowscan=shadowscan_core.main:main
    ''',
)