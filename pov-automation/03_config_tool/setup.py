from setuptools import setup

with open('README.md') as f:
    long_description = f.read()

setup(name='prisma_config',
      version='6.5.1b2',
      description='Configuration exporting and Continuous Integration (CI) capable configuration importing for the '
                  'Prisma SDWAN Cloud Controller.',
      long_description=long_description,
      long_description_content_type='text/markdown',
      url='https://github.com/PaloAltoNetworks/prisma_config',
      author='Prisma SASE Developer Support',
      author_email='prisma-sase-developers@paloaltonetworks.com',
      license='MIT',
      install_requires=[
            'prisma_sase >= 6.5.1b1, < 6.5.2b1',
            'PyYAML >= 5.3'
      ],
      packages=['prisma_config'],
      entry_points={
            'console_scripts': [
                  'do_site = prisma_config.do:go',
                  'pull_site = prisma_config.pull:go',
                  ]
      },
      classifiers=[
            "Development Status :: 4 - Beta",
            "Intended Audience :: Developers",
            "License :: OSI Approved :: MIT License",
            "Programming Language :: Python :: 2.7",
            "Programming Language :: Python :: 3.6",
            "Programming Language :: Python :: 3.7",
            "Programming Language :: Python :: 3.8"
      ]
      )
