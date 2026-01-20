from setuptools import setup, find_packages

setup(
    name='shadowscan',
    version='1.1',
    description='Offensive OSINT Framework',
    author='Sibasundar Barik',
    packages=find_packages(),      
    py_modules=['main'],           
    install_requires=[
        'requests', 'rich', 'pyfiglet', 'easyocr', 
        'spacy', 'exifread', 'textblob', 'thefuzz', 'pillow-heif'
    ],
    entry_points='''
        [console_scripts]
        shadowscan=main:main
    ''',
)