from time import time
import setuptools
with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()
setuptools.setup(
    name='abstract_logins',
    version='0.0.0.24',
    author='putkoff',
    author_email='partners@abstractendeavors.com',
    description='The `abstract_apis` module is designed to facilitate HTTP requests in Python applications, particularly those that require handling JSON data, dealing with custom API endpoints, and parsing complex nested JSON responses. The module simplifies request handling by abstracting away common tasks such as header management, URL construction, and response parsing.',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/AbstractEndeavors/abstract_logins',
    package_dir={"": "src"},
    packages=setuptools.find_packages(where="src"),
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'Topic :: Software Development :: Libraries',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
    ],
    install_requires=['abstract_utilities','abstract_security','abstract_flask','psycopg2','abstract_database','abstract_ai'],
    python_requires=">=3.6",
    # Add this line to include wheel format in your distribution
    setup_requires=['wheel'],
)
