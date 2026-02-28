#!/usr/bin/env python3
"""
Anti-Ransomware CI/CD Pipeline
GitHub Actions, GitLab CI, and Jenkins pipeline definitions
"""

import os
import yaml
import json
from pathlib import Path
from typing import Dict, Any

class CICDManager:
    """CI/CD pipeline configuration manager"""
    
    def __init__(self):
        self.project_name = "anti-ransomware"
        self.version = "1.0.0"
    
    def create_github_actions(self) -> bool:
        """Create GitHub Actions workflows"""
        try:
            # Create .github/workflows directory
            workflows_dir = Path(".github/workflows")
            workflows_dir.mkdir(parents=True, exist_ok=True)
            
            # Main CI/CD workflow
            main_workflow = {
                'name': 'Anti-Ransomware CI/CD',
                'on': {
                    'push': {
                        'branches': ['main', 'develop']
                    },
                    'pull_request': {
                        'branches': ['main']
                    },
                    'release': {
                        'types': ['created']
                    }
                },
                'env': {
                    'PYTHON_VERSION': '3.11',
                    'DOCKER_REGISTRY': 'ghcr.io',
                    'IMAGE_NAME': 'antiransomware/anti-ransomware'
                },
                'jobs': {
                    'test': {
                        'name': 'Run Tests',
                        'runs-on': 'ubuntu-latest',
                        'strategy': {
                            'matrix': {
                                'os': ['ubuntu-latest', 'windows-latest', 'macos-latest'],
                                'python-version': ['3.10', '3.11', '3.12']
                            }
                        },
                        'steps': [
                            {
                                'name': 'Checkout code',
                                'uses': 'actions/checkout@v4'
                            },
                            {
                                'name': 'Set up Python ${{ matrix.python-version }}',
                                'uses': 'actions/setup-python@v4',
                                'with': {
                                    'python-version': '${{ matrix.python-version }}'
                                }
                            },
                            {
                                'name': 'Install dependencies',
                                'run': '''
pip install --upgrade pip
pip install -r requirements.txt
pip install pytest pytest-cov flake8 black mypy
                                '''
                            },
                            {
                                'name': 'Lint with flake8',
                                'run': '''
flake8 . --count --select=E9,F63,F7,F82 --show-source --statistics
flake8 . --count --exit-zero --max-complexity=10 --max-line-length=127 --statistics
                                '''
                            },
                            {
                                'name': 'Check code formatting with black',
                                'run': 'black --check .'
                            },
                            {
                                'name': 'Type checking with mypy',
                                'run': 'mypy . --ignore-missing-imports'
                            },
                            {
                                'name': 'Run tests',
                                'run': 'pytest --cov=. --cov-report=xml'
                            },
                            {
                                'name': 'Upload coverage to Codecov',
                                'uses': 'codecov/codecov-action@v3',
                                'with': {
                                    'file': './coverage.xml'
                                }
                            }
                        ]
                    },
                    'security-scan': {
                        'name': 'Security Scan',
                        'runs-on': 'ubuntu-latest',
                        'steps': [
                            {
                                'name': 'Checkout code',
                                'uses': 'actions/checkout@v4'
                            },
                            {
                                'name': 'Run Bandit Security Scan',
                                'uses': 'securecodewarrior/github-action-bandit@v1.0.1',
                                'with': {
                                    'config_file': '.bandit'
                                }
                            },
                            {
                                'name': 'Run Safety check',
                                'run': '''
pip install safety
safety check -r requirements.txt
                                '''
                            },
                            {
                                'name': 'Scan for secrets',
                                'uses': 'trufflesecurity/trufflehog@v3.63.2-beta',
                                'with': {
                                    'path': './',
                                    'base': '${{ github.event.repository.default_branch }}',
                                    'head': 'HEAD'
                                }
                            }
                        ]
                    },
                    'build-cross-platform': {
                        'name': 'Build Cross-Platform',
                        'runs-on': '${{ matrix.os }}',
                        'needs': ['test', 'security-scan'],
                        'strategy': {
                            'matrix': {
                                'os': ['ubuntu-latest', 'windows-latest', 'macos-latest']
                            }
                        },
                        'steps': [
                            {
                                'name': 'Checkout code',
                                'uses': 'actions/checkout@v4'
                            },
                            {
                                'name': 'Set up Python',
                                'uses': 'actions/setup-python@v4',
                                'with': {
                                    'python-version': '${{ env.PYTHON_VERSION }}'
                                }
                            },
                            {
                                'name': 'Install dependencies',
                                'run': '''
pip install --upgrade pip
pip install -r requirements.txt
                                '''
                            },
                            {
                                'name': 'Build with deployment script',
                                'run': 'python deployment.py build'
                            },
                            {
                                'name': 'Upload build artifacts',
                                'uses': 'actions/upload-artifact@v3',
                                'with': {
                                    'name': 'build-${{ matrix.os }}',
                                    'path': 'dist/'
                                }
                            }
                        ]
                    },
                    'docker-build': {
                        'name': 'Build Docker Image',
                        'runs-on': 'ubuntu-latest',
                        'needs': ['build-cross-platform'],
                        'if': "github.event_name == 'release' || github.ref == 'refs/heads/main'",
                        'steps': [
                            {
                                'name': 'Checkout code',
                                'uses': 'actions/checkout@v4'
                            },
                            {
                                'name': 'Set up Docker Buildx',
                                'uses': 'docker/setup-buildx-action@v3'
                            },
                            {
                                'name': 'Login to Container Registry',
                                'uses': 'docker/login-action@v3',
                                'with': {
                                    'registry': '${{ env.DOCKER_REGISTRY }}',
                                    'username': '${{ github.actor }}',
                                    'password': '${{ secrets.GITHUB_TOKEN }}'
                                }
                            },
                            {
                                'name': 'Extract metadata',
                                'id': 'meta',
                                'uses': 'docker/metadata-action@v5',
                                'with': {
                                    'images': '${{ env.DOCKER_REGISTRY }}/${{ env.IMAGE_NAME }}',
                                    'tags': '''
type=ref,event=branch
type=ref,event=pr
type=semver,pattern={{version}}
type=semver,pattern={{major}}.{{minor}}
                                    '''
                                }
                            },
                            {
                                'name': 'Build and push Docker image',
                                'uses': 'docker/build-push-action@v5',
                                'with': {
                                    'context': '.',
                                    'push': True,
                                    'tags': '${{ steps.meta.outputs.tags }}',
                                    'labels': '${{ steps.meta.outputs.labels }}',
                                    'platforms': 'linux/amd64,linux/arm64'
                                }
                            }
                        ]
                    },
                    'deploy-staging': {
                        'name': 'Deploy to Staging',
                        'runs-on': 'ubuntu-latest',
                        'needs': ['docker-build'],
                        'if': "github.ref == 'refs/heads/develop'",
                        'environment': 'staging',
                        'steps': [
                            {
                                'name': 'Deploy to staging environment',
                                'run': '''
echo "Deploying to staging..."
# Add staging deployment commands here
                                '''
                            }
                        ]
                    },
                    'deploy-production': {
                        'name': 'Deploy to Production',
                        'runs-on': 'ubuntu-latest',
                        'needs': ['docker-build'],
                        'if': "github.event_name == 'release'",
                        'environment': 'production',
                        'steps': [
                            {
                                'name': 'Deploy to production environment',
                                'run': '''
echo "Deploying to production..."
# Add production deployment commands here
                                '''
                            }
                        ]
                    }
                }
            }
            
            # Write main workflow
            with open(workflows_dir / "main.yml", 'w') as f:
                yaml.dump(main_workflow, f, default_flow_style=False, sort_keys=False)
            
            # Create code quality workflow
            code_quality_workflow = {
                'name': 'Code Quality',
                'on': {
                    'push': {'branches': ['main', 'develop']},
                    'pull_request': {'branches': ['main']}
                },
                'jobs': {
                    'code-quality': {
                        'runs-on': 'ubuntu-latest',
                        'steps': [
                            {
                                'name': 'Checkout code',
                                'uses': 'actions/checkout@v4'
                            },
                            {
                                'name': 'Set up Python',
                                'uses': 'actions/setup-python@v4',
                                'with': {'python-version': '3.11'}
                            },
                            {
                                'name': 'Install quality tools',
                                'run': 'pip install black flake8 mypy bandit safety'
                            },
                            {
                                'name': 'Run Black formatter',
                                'run': 'black --check --diff .'
                            },
                            {
                                'name': 'Run Flake8 linter',
                                'run': 'flake8 . --max-line-length=127'
                            },
                            {
                                'name': 'Run MyPy type checker',
                                'run': 'mypy . --ignore-missing-imports'
                            },
                            {
                                'name': 'Run Bandit security linter',
                                'run': 'bandit -r . -x ./test_*'
                            },
                            {
                                'name': 'Check dependencies for vulnerabilities',
                                'run': 'safety check'
                            }
                        ]
                    }
                }
            }
            
            with open(workflows_dir / "code-quality.yml", 'w') as f:
                yaml.dump(code_quality_workflow, f, default_flow_style=False)
            
            print("GitHub Actions workflows created")
            return True
            
        except Exception as e:
            print(f"Failed to create GitHub Actions workflows: {e}")
            return False
    
    def create_gitlab_ci(self) -> bool:
        """Create GitLab CI configuration"""
        try:
            gitlab_ci = {
                'stages': ['test', 'security', 'build', 'deploy'],
                'variables': {
                    'DOCKER_REGISTRY': 'registry.gitlab.com',
                    'IMAGE_NAME': '$CI_PROJECT_PATH',
                    'PYTHON_VERSION': '3.11'
                },
                'before_script': [
                    'python --version',
                    'pip install --upgrade pip',
                    'pip install -r requirements.txt'
                ],
                'test:python': {
                    'stage': 'test',
                    'image': 'python:3.11',
                    'parallel': {
                        'matrix': [
                            {'PYTHON_VERSION': '3.10'},
                            {'PYTHON_VERSION': '3.11'},
                            {'PYTHON_VERSION': '3.12'}
                        ]
                    },
                    'script': [
                        'pip install pytest pytest-cov',
                        'pytest --cov=. --cov-report=xml'
                    ],
                    'artifacts': {
                        'reports': {'coverage_report': {'coverage_format': 'cobertura', 'path': 'coverage.xml'}}
                    }
                },
                'security:bandit': {
                    'stage': 'security',
                    'image': 'python:3.11',
                    'script': [
                        'pip install bandit',
                        'bandit -r . -f json -o bandit-report.json'
                    ],
                    'artifacts': {
                        'reports': {'sast': 'bandit-report.json'}
                    },
                    'allow_failure': True
                },
                'security:safety': {
                    'stage': 'security',
                    'image': 'python:3.11',
                    'script': [
                        'pip install safety',
                        'safety check --json --output safety-report.json'
                    ],
                    'artifacts': {
                        'reports': {'dependency_scanning': 'safety-report.json'}
                    },
                    'allow_failure': True
                },
                'build:cross-platform': {
                    'stage': 'build',
                    'parallel': {
                        'matrix': [
                            {'PLATFORM': 'linux', 'ARCH': 'amd64'},
                            {'PLATFORM': 'linux', 'ARCH': 'arm64'},
                            {'PLATFORM': 'windows', 'ARCH': 'amd64'},
                            {'PLATFORM': 'darwin', 'ARCH': 'amd64'}
                        ]
                    },
                    'script': [
                        'python deployment.py build $PLATFORM $ARCH'
                    ],
                    'artifacts': {
                        'paths': ['dist/'],
                        'expire_in': '1 week'
                    }
                },
                'build:docker': {
                    'stage': 'build',
                    'image': 'docker:latest',
                    'services': ['docker:dind'],
                    'before_script': [
                        'docker login -u $CI_REGISTRY_USER -p $CI_REGISTRY_PASSWORD $CI_REGISTRY'
                    ],
                    'script': [
                        'docker build -t $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA .',
                        'docker push $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA',
                        'docker tag $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA $CI_REGISTRY_IMAGE:latest',
                        'docker push $CI_REGISTRY_IMAGE:latest'
                    ],
                    'only': ['main', 'tags']
                },
                'deploy:staging': {
                    'stage': 'deploy',
                    'script': [
                        'echo "Deploying to staging..."',
                        '# Add staging deployment commands'
                    ],
                    'environment': {
                        'name': 'staging',
                        'url': 'https://staging.example.com'
                    },
                    'only': ['develop']
                },
                'deploy:production': {
                    'stage': 'deploy',
                    'script': [
                        'echo "Deploying to production..."',
                        '# Add production deployment commands'
                    ],
                    'environment': {
                        'name': 'production',
                        'url': 'https://example.com'
                    },
                    'only': ['tags'],
                    'when': 'manual'
                }
            }
            
            with open(".gitlab-ci.yml", 'w') as f:
                yaml.dump(gitlab_ci, f, default_flow_style=False)
            
            print("GitLab CI configuration created")
            return True
            
        except Exception as e:
            print(f"Failed to create GitLab CI configuration: {e}")
            return False
    
    def create_jenkins_pipeline(self) -> bool:
        """Create Jenkins pipeline configuration"""
        try:
            jenkinsfile = '''pipeline {
    agent any
    
    parameters {
        choice(
            name: 'BUILD_TYPE',
            choices: ['development', 'staging', 'production'],
            description: 'Build type'
        )
        booleanParam(
            name: 'DEPLOY_TO_STAGING',
            defaultValue: false,
            description: 'Deploy to staging environment'
        )
    }
    
    environment {
        PYTHON_VERSION = '3.11'
        DOCKER_REGISTRY = credentials('docker-registry')
        IMAGE_NAME = 'antiransomware/anti-ransomware'
    }
    
    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }
        
        stage('Setup Python') {
            steps {
                sh '''
                    python${PYTHON_VERSION} -m venv venv
                    . venv/bin/activate
                    pip install --upgrade pip
                    pip install -r requirements.txt
                '''
            }
        }
        
        stage('Code Quality') {
            parallel {
                stage('Lint') {
                    steps {
                        sh '''
                            . venv/bin/activate
                            flake8 . --max-line-length=127
                        '''
                    }
                }
                stage('Format Check') {
                    steps {
                        sh '''
                            . venv/bin/activate
                            black --check .
                        '''
                    }
                }
                stage('Type Check') {
                    steps {
                        sh '''
                            . venv/bin/activate
                            mypy . --ignore-missing-imports
                        '''
                    }
                }
            }
        }
        
        stage('Security Scan') {
            parallel {
                stage('Bandit') {
                    steps {
                        sh '''
                            . venv/bin/activate
                            bandit -r . -f json -o bandit-report.json
                        '''
                        publishHTML([
                            allowMissing: false,
                            alwaysLinkToLastBuild: true,
                            keepAll: true,
                            reportDir: '.',
                            reportFiles: 'bandit-report.json',
                            reportName: 'Bandit Security Report'
                        ])
                    }
                }
                stage('Safety') {
                    steps {
                        sh '''
                            . venv/bin/activate
                            safety check
                        '''
                    }
                }
            }
        }
        
        stage('Test') {
            steps {
                sh '''
                    . venv/bin/activate
                    pytest --cov=. --cov-report=xml --junitxml=test-results.xml
                '''
                publishTestResults testResultsPattern: 'test-results.xml'
                publishCoverage adapters: [coberturaAdapter('coverage.xml')], sourceFileResolver: sourceFiles('STORE_LAST_BUILD')
            }
        }
        
        stage('Build Cross-Platform') {
            parallel {
                stage('Build Linux') {
                    steps {
                        sh '''
                            . venv/bin/activate
                            python deployment.py build linux amd64
                        '''
                    }
                }
                stage('Build Windows') {
                    steps {
                        sh '''
                            . venv/bin/activate
                            python deployment.py build windows amd64
                        '''
                    }
                }
                stage('Build macOS') {
                    steps {
                        sh '''
                            . venv/bin/activate
                            python deployment.py build darwin amd64
                        '''
                    }
                }
            }
        }
        
        stage('Build Docker Image') {
            when {
                anyOf {
                    branch 'main'
                    branch 'develop'
                    buildingTag()
                }
            }
            steps {
                script {
                    def image = docker.build("${IMAGE_NAME}:${BUILD_NUMBER}")
                    docker.withRegistry('https://registry.hub.docker.com', 'docker-hub-credentials') {
                        image.push()
                        image.push('latest')
                    }
                }
            }
        }
        
        stage('Deploy to Staging') {
            when {
                anyOf {
                    branch 'develop'
                    params.DEPLOY_TO_STAGING == true
                }
            }
            steps {
                sh 'python deployment.py deploy staging'
            }
        }
        
        stage('Deploy to Production') {
            when {
                buildingTag()
            }
            input {
                message "Deploy to production?"
                ok "Deploy"
                parameters {
                    choice(
                        name: 'ENVIRONMENT',
                        choices: ['production'],
                        description: 'Target environment'
                    )
                }
            }
            steps {
                sh 'python deployment.py deploy production'
            }
        }
    }
    
    post {
        always {
            archiveArtifacts artifacts: 'dist/**/*', fingerprint: true
            cleanWs()
        }
        success {
            emailext (
                subject: "Build Successful: ${env.JOB_NAME} - ${env.BUILD_NUMBER}",
                body: "Build ${env.BUILD_NUMBER} of ${env.JOB_NAME} completed successfully.",
                to: "${env.CHANGE_AUTHOR_EMAIL}"
            )
        }
        failure {
            emailext (
                subject: "Build Failed: ${env.JOB_NAME} - ${env.BUILD_NUMBER}",
                body: "Build ${env.BUILD_NUMBER} of ${env.JOB_NAME} failed. Check console output for details.",
                to: "${env.CHANGE_AUTHOR_EMAIL}"
            )
        }
    }
}'''
            
            with open("Jenkinsfile", 'w') as f:
                f.write(jenkinsfile)
            
            print("Jenkins pipeline configuration created")
            return True
            
        except Exception as e:
            print(f"Failed to create Jenkins pipeline: {e}")
            return False
    
    def create_quality_configs(self) -> bool:
        """Create code quality configuration files"""
        try:
            # Black configuration
            pyproject_toml = '''[tool.black]
line-length = 127
target-version = ['py311']
include = '\.pyi?$'
exclude = '''
/(
    \.eggs
  | \.git
  | \.hg
  | \.mypy_cache
  | \.tox
  | \.venv
  | _build
  | buck-out
  | build
  | dist
)/
'''
'''
            
            # Flake8 configuration  
            flake8_config = '''[flake8]
max-line-length = 127
exclude = .git,__pycache__,dist,build,*.egg
ignore = E203,W503,W504
per-file-ignores = __init__.py:F401
'''
            
            # MyPy configuration
            mypy_config = '''[mypy]
python_version = 3.11
warn_return_any = True
warn_unused_configs = True
disallow_untyped_defs = True
ignore_missing_imports = True
'''
            
            # Bandit configuration
            bandit_config = '''[bandit]
exclude_dirs = ["*/test_*", "*/tests/*"]
skips = ["B101", "B601"]
'''
            
            # Pytest configuration
            pytest_config = '''[tool.pytest.ini_options]
minversion = "6.0"
addopts = "-ra -q --strict-markers --strict-config"
testpaths = [
    "tests",
]
markers = [
    "slow: marks tests as slow (deselect with '-m \"not slow\"')",
    "integration: marks tests as integration tests",
]
'''
            
            # Write configuration files
            with open("pyproject.toml", 'w') as f:
                f.write(pyproject_toml)
                f.write(pytest_config)
            
            with open(".flake8", 'w') as f:
                f.write(flake8_config)
            
            with open("mypy.ini", 'w') as f:
                f.write(mypy_config)
            
            with open(".bandit", 'w') as f:
                f.write(bandit_config)
            
            print("Code quality configurations created")
            return True
            
        except Exception as e:
            print(f"Failed to create quality configurations: {e}")
            return False
    
    def create_all_pipelines(self) -> bool:
        """Create all CI/CD pipeline configurations"""
        success = True
        
        print("Creating CI/CD pipeline configurations...")
        
        if not self.create_github_actions():
            success = False
        
        if not self.create_gitlab_ci():
            success = False
        
        if not self.create_jenkins_pipeline():
            success = False
        
        if not self.create_quality_configs():
            success = False
        
        if success:
            print("All CI/CD pipeline configurations created successfully!")
        else:
            print("Some CI/CD configurations failed to create")
        
        return success

def main():
    """Main CI/CD configuration script"""
    cicd_manager = CICDManager()
    
    if len(os.sys.argv) > 1:
        command = os.sys.argv[1]
        
        if command == "github":
            success = cicd_manager.create_github_actions()
        elif command == "gitlab":
            success = cicd_manager.create_gitlab_ci()
        elif command == "jenkins":
            success = cicd_manager.create_jenkins_pipeline()
        elif command == "quality":
            success = cicd_manager.create_quality_configs()
        elif command == "all":
            success = cicd_manager.create_all_pipelines()
        else:
            print(f"Unknown command: {command}")
            print("Available commands: github, gitlab, jenkins, quality, all")
            return 1
    else:
        success = cicd_manager.create_all_pipelines()
    
    return 0 if success else 1

if __name__ == "__main__":
    exit(main())
