from setuptools import setup, find_packages

setup(
    name='sso_integration',
    version='1.0.0',
    description='Single Sign-On integration for Frappe/ERPNext v15',
    author='Eng. Abdullah Dheir',
    author_email='abdullah.dheir@gmail.com',
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        'frappe>=15.0.0',
    ],
    zip_safe=False,
)
