from setuptools import setup, find_packages

setup(
    name='destinelab',
    version='1.0',
    packages=find_packages(),
    install_requires=[
        'requests',
        'lxml',
        'PyJWT',
    ],
)
