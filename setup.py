from setuptools import setup, find_packages

setup(
    name="advanced_logger",  
    version="0.0.4",  
    author="Dustan Gunn",  
    author_email="sweepscafe@gmail.com", 
    description="An advanced Python logging library with context, cloud support, and more",
    long_description=open('README.md').read(),  # Read the long description from the README file
    long_description_content_type="text/markdown",  # Specify Markdown for the README
    url="https://github.com/dgunn420/advancedlogger", 
    packages=find_packages(where='.', exclude=("tests",)),  
    classifiers=[  
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GPL License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.12",  
    install_requires=[  
        "boto3",  # For AWS CloudWatch
        "requests",  # For Splunk integration
    ],
    extras_require={ 
        "dev": [
            "pytest", 
            "tox",  
        ]
    },
    entry_points={  
        'console_scripts': [
            'log-utility=advanced_logger.logger:main', 
        ]
    },
    include_package_data=True,  
    package_data={  
        '': ['README.md', 'LICENSE'],
    },
)
