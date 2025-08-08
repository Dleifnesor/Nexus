"""
Nexus AI-Powered Penetration Testing Tool
Setup configuration for installation and distribution with Kali Linux optimization
"""

from setuptools import setup, find_packages
import os
import sys

# Read the README file
def read_readme():
    readme_path = os.path.join(os.path.dirname(__file__), 'README.md')
    if os.path.exists(readme_path):
        with open(readme_path, 'r', encoding='utf-8') as f:
            return f.read()
    return "Nexus AI-Powered Penetration Testing Tool with Autonomous AI Agent"

# Read requirements with error handling
def read_requirements():
    requirements_path = os.path.join(os.path.dirname(__file__), 'requirements.txt')
    if os.path.exists(requirements_path):
        try:
            with open(requirements_path, 'r', encoding='utf-8') as f:
                requirements = []
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        requirements.append(line)
                return requirements
        except Exception as e:
            print(f"Warning: Could not read requirements.txt: {e}")
            return get_minimal_requirements()
    return get_minimal_requirements()

# Minimal requirements for fallback
def get_minimal_requirements():
    return [
        "click>=8.0.0",
        "pyyaml>=6.0",
        "requests>=2.28.0",
        "aiohttp>=3.8.0",
        "networkx>=2.8.0",
        "colorama>=0.4.4",
        "rich>=13.0.0",
        "asyncio",
    ]

# Check if running on Kali Linux
def is_kali_linux():
    try:
        with open("/etc/os-release", "r") as f:
            content = f.read()
            return "Kali" in content or "kali" in content.lower()
    except FileNotFoundError:
        return False

# Get Kali-specific requirements
def get_kali_requirements():
    return [
        "python-libnmap>=0.7.3",
        "pexpect>=4.8.0",
        "ptyprocess>=0.7.0",
        "scapy>=2.4.5",
        "python-nmap>=0.7.1",
        "dnspython>=2.2.0",
        "netaddr>=0.8.0",
        "paramiko>=2.11.0",
        "cryptography>=3.4.8",
        "beautifulsoup4>=4.11.0",
        "lxml>=4.9.0",
    ]

# Combine requirements
base_requirements = read_requirements()

# Add Kali-specific requirements if on Kali
if is_kali_linux():
    print("Kali Linux detected - adding Kali-specific requirements")
    kali_reqs = get_kali_requirements()
    for req in kali_reqs:
        req_name = req.split(">=")[0].split("==")[0].split("[")[0]
        # Only add if not already in base requirements
        if not any(req_name in base_req for base_req in base_requirements):
            base_requirements.append(req)

setup(
    name="nexus-pentest",
    version="1.0.0",
    author="Nexus Security Team",
    author_email="security@nexus-security.com",
    description="AI-Powered Penetration Testing Tool with Autonomous AI Agent and Advanced Evasion",
    long_description=read_readme(),
    long_description_content_type="text/markdown",
    url="https://github.com/nexus-security/nexus",
    packages=find_packages(exclude=["tests*", "docs*"]),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "Topic :: Security",
        "Topic :: System :: Networking :: Monitoring",
        "Topic :: System :: Systems Administration",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: POSIX :: Linux",
        "Operating System :: Unix",
        "Environment :: Console",
        "Natural Language :: English",
    ],
    python_requires=">=3.9",
    install_requires=base_requirements,
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-asyncio>=0.21.0",
            "pytest-cov>=4.0.0",
            "black>=23.0.0",
            "flake8>=6.0.0",
            "mypy>=1.0.0",
            "pre-commit>=3.0.0",
            "isort>=5.10.0",
            "bandit>=1.7.0",
        ],
        "docs": [
            "sphinx>=6.0.0",
            "sphinx-rtd-theme>=1.2.0",
            "myst-parser>=1.0.0",
            "sphinx-click>=4.3.0",
        ],
        "kali": get_kali_requirements(),
        "ai": [
            "scikit-learn>=1.1.0",
            "numpy>=1.21.0",
            "pandas>=1.5.0",
        ],
        "visualization": [
            "matplotlib>=3.5.0",
            "plotly>=5.10.0",
            "graphviz>=0.20.0",
        ],
        "reporting": [
            "jinja2>=3.0.0",
            "markdown>=3.4.0",
        ],
        "full": [
            # All optional dependencies
            "scikit-learn>=1.1.0",
            "numpy>=1.21.0",
            "pandas>=1.5.0",
            "matplotlib>=3.5.0",
            "plotly>=5.10.0",
            "graphviz>=0.20.0",
            "jinja2>=3.0.0",
            "markdown>=3.4.0",
        ] + get_kali_requirements(),
    },
    entry_points={
        "console_scripts": [
            "nexus=nexus.cli.main:main",
        ],
    },
    include_package_data=True,
    package_data={
        "nexus": [
            "config/*.yaml",
            "config/*.yml",
            "config/prompts/*.txt",
            "config/prompts/*.md",
            "templates/*.yaml",
            "templates/*.yml",
            "templates/*.html",
            "templates/*.jinja2",
            "templates/*.j2",
            "data/*.json",
            "data/*.yaml",
            "data/*.yml",
            "ai/prompts/*.txt",
            "ai/prompts/*.md",
        ],
    },
    data_files=[
        ("share/nexus/config", [
            "config/default.yaml", 
            "config/kali_tools.yaml",
        ]),
        ("share/nexus/docs", [
            "README.md",
        ]),
        ("share/nexus/scripts", ["scripts/install.sh"]),
    ] if os.path.exists("config/default.yaml") else [],
    zip_safe=False,
    keywords=[
        "penetration testing",
        "security",
        "ai",
        "automation",
        "red team",
        "cybersecurity",
        "vulnerability assessment",
        "ethical hacking",
        "kali linux",
        "autonomous",
        "evasion",
        "stealth",
        "ai-powered",
        "natural language",
    ],
    project_urls={
        "Bug Reports": "https://github.com/nexus-security/nexus/issues",
        "Source": "https://github.com/nexus-security/nexus",
        "Documentation": "https://nexus-security.github.io/nexus/",
        "Changelog": "https://github.com/nexus-security/nexus/blob/main/CHANGELOG.md",
        "Discussions": "https://github.com/nexus-security/nexus/discussions",
    },
    # Platform-specific configurations
    platforms=["linux"],
    # Ensure compatibility with Kali Linux Python environment
    setup_requires=["wheel", "setuptools>=65.0.0"],
    # Additional metadata for Kali Linux compatibility
    options={
        "build_scripts": {
            "executable": "/usr/bin/python3",
        },
    },
)