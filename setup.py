from os import path

from setuptools import setup

this_directory = path.abspath(path.dirname(__file__))  # pylint: disable=invalid-name
with open(path.join(this_directory, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()  # pylint: disable=invalid-name

setup(name='drb_client',
      version='0.2.2',
      description='Distributed Randomness Beacon client',
      url='https://github.com/Snawoot/drb-client',
      author='Vladislav Yarmak',
      author_email='vladislav-ex-src@vm-0.com',
      license='MIT',
      packages=['drb_client'],
      python_requires='>=3.5.3',
      setup_requires=[
          'wheel',
      ],
      install_requires=[
          'aiohttp>=3.4.4',
          'sdnotify>=0.3.2',
          'cryptography>=2.0',
          'toml',
          'async_exit_stack',
      ],
      entry_points={
          'console_scripts': [
              'drb-client=drb_client.__main__:main',
          ],
      },
      classifiers=[
          "Programming Language :: Python :: 3.5",
          "License :: OSI Approved :: MIT License",
          "Operating System :: POSIX :: Linux",
          "Development Status :: 4 - Beta",
          "Environment :: No Input/Output (Daemon)",
          "Intended Audience :: System Administrators",
          "Natural Language :: English",
          "Topic :: Internet",
          "Topic :: Security",
          "Topic :: System :: Operating System Kernels :: Linux",
          "Topic :: Security :: Cryptography",
          "Topic :: Utilities",
      ],
      long_description=long_description,
      long_description_content_type='text/markdown',
      zip_safe=True)
