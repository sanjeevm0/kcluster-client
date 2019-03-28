from setuptools import setup
import re

# change == to >=
def load_reqs(filename):
    with open(filename) as reqs_file:
        return [
            re.sub('==', '>=', line) for line in reqs_file.readlines()
            if not re.match(r'\s*#', line)
        ]

requirements = load_reqs('requirements.txt')

setup(
    name='kcclient',
    version='0.1',
    description='A REST client for KCluster',
    url='http://github.com/sanjeevm0/kcluster-client',
    author='Sanjeev Mehrotra',
    author_email='sanjeevm@microsoft.com',
    license='MIT',
    packages=['kcclient'],
    install_requires=requirements
)
