from setuptools import setup, find_packages

setup(
    name='shadowscan',
    version='1.0',
    packages=find_packages(),
    install_requires=[
        'requests', 'rich', 'pyfiglet', 'easyocr', 
        'spacy', 'exifread', 'beautifulsoup4', 'colorama' , 'python-Levenshtein', 'pyap', 'pillow', 'textblob', 'thefuzz', 'pillow-heif'
    ],
    entry_points='''
        [console_scripts]
        shadowscan=main:main
    ''',
)