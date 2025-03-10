from setuptools import setup, find_packages

setup(
    name="shadowscan",
    version="0.1",
    packages=find_packages(),
    install_requires=[
        'requests',
        'colorama',
        'tqdm'  # Eğer projede kullanılıyorsa
    ],
    entry_points={
        "console_scripts": [
            "shadowscan=shadowscan.shadowscan:main"  # Doğru entry point
        ]
    },
    python_requires='>=3.6',
    # Eğer Python 3.7 veya daha yüksek bir sürüm gerekiyorsa
    python_requires='>=3.7',
    description="A comprehensive shadow scanning tool for sensitive data and security vulnerabilities.",
    author="Your Name",
    author_email="your.email@example.com",
)