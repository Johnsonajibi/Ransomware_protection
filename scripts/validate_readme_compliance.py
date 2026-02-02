#!/usr/bin/env python3
"""
Validate README Compliance
Validate that all code examples in README files are consistent and accurate.
"""

import os
import sys
import re
import json
import logging
import argparse
from pathlib import Path
from typing import List, Dict, Tuple

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('readme_compliance_check.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class ReadmeComplianceValidator:
    def __init__(self):
        self.readme_files = []
        self.python_scripts = set()
        self.code_examples = []
        self.missing_scripts = []
        self.inconsistencies = []
    
    def find_readme_files(self) -> List[Path]:
        """Find all README files in the repository"""
        logger.info("Searching for README files...")
        
        readme_patterns = ['README*.md', 'readme*.md', '*README.md']
        found_files = []
        
        for pattern in readme_patterns:
            found_files.extend(Path('.').glob(f'**/{pattern}'))
        
        # Remove duplicates
        found_files = list(set(found_files))
        
        logger.info(f"Found {len(found_files)} README files")
        self.readme_files = found_files
        
        return found_files
    
    def find_python_scripts(self) -> set:
        """Find all Python scripts in root directory"""
        logger.info("Scanning for Python scripts...")
        
        scripts = set()
        for py_file in Path('.').glob('*.py'):
            scripts.add(py_file.name)
        
        logger.info(f"Found {len(scripts)} Python scripts")
        self.python_scripts = scripts
        
        return scripts
    
    def extract_code_examples(self) -> List[Dict]:
        """Extract all code examples from README files"""
        logger.info("\nExtracting code examples from READMEs...")
        
        examples = []
        
        for readme_file in self.readme_files:
            try:
                content = readme_file.read_text()
                
                # Find code blocks with python commands
                pattern = r'```(?:bash|python|sh)?\s*\n(.*?)\n```'
                matches = re.finditer(pattern, content, re.DOTALL)
                
                for match in matches:
                    code_block = match.group(1)
                    
                    # Extract python script calls
                    python_pattern = r'python\s+(\S+\.py)(?:\s+(.*))?'
                    python_matches = re.finditer(python_pattern, code_block)
                    
                    for py_match in python_matches:
                        script_name = py_match.group(1)
                        arguments = py_match.group(2) or ''
                        
                        examples.append({
                            'file': str(readme_file),
                            'script': script_name,
                            'arguments': arguments,
                            'context': code_block[:100]
                        })
            
            except Exception as e:
                logger.warning(f"Error processing {readme_file}: {e}")
        
        self.code_examples = examples
        logger.info(f"Found {len(examples)} code examples")
        
        return examples
    
    def validate_script_existence(self) -> bool:
        """Check if all referenced scripts actually exist"""
        logger.info("\nValidating script existence...")
        
        missing = []
        found = []
        
        for example in self.code_examples:
            script = example['script']
            
            # Check if script exists
            if script in self.python_scripts:
                found.append(script)
            else:
                missing.append({
                    'script': script,
                    'referenced_in': example['file'],
                    'arguments': example['arguments']
                })
        
        if missing:
            logger.error(f"\n❌ {len(missing)} missing scripts referenced:")
            for item in missing:
                logger.error(f"   - {item['script']} (referenced in {Path(item['referenced_in']).name})")
            self.missing_scripts = missing
            return False
        else:
            logger.info(f"✓ All {len(found)} referenced scripts exist")
            return True
    
    def check_argument_consistency(self) -> bool:
        """Check if argument usage is consistent across examples"""
        logger.info("\nChecking argument consistency...")
        
        script_args = {}
        inconsistent = []
        
        for example in self.code_examples:
            script = example['script']
            args = example['arguments'].strip()
            
            if script not in script_args:
                script_args[script] = set()
            
            script_args[script].add(args)
        
        # Find scripts with varying arguments
        for script, args_set in script_args.items():
            if len(args_set) > 1:
                inconsistent.append({
                    'script': script,
                    'variations': list(args_set)
                })
        
        if inconsistent:
            logger.warning(f"\n⚠️  Found {len(inconsistent)} scripts with varying usage:")
            for item in inconsistent:
                logger.warning(f"   - {item['script']}:")
                for arg_variant in item['variations']:
                    logger.warning(f"     • {arg_variant if arg_variant else '(no args)'}")
            self.inconsistencies = inconsistent
            return False
        else:
            logger.info("✓ Argument usage is consistent")
            return True
    
    def validate_help_output(self) -> bool:
        """Test --help output for referenced scripts"""
        logger.info("\nValidating --help output...")
        
        import subprocess
        
        tested_scripts = set()
        success_count = 0
        fail_count = 0
        
        for example in self.code_examples:
            script = example['script']
            
            if script not in tested_scripts and script in self.python_scripts:
                tested_scripts.add(script)
                
                try:
                    result = subprocess.run(
                        [sys.executable, script, '--help'],
                        capture_output=True,
                        text=True,
                        timeout=5
                    )
                    
                    if result.returncode == 0 and 'usage:' in result.stdout.lower():
                        logger.info(f"   ✓ {script}")
                        success_count += 1
                    else:
                        logger.warning(f"   ⚠️  {script} (unexpected output)")
                        fail_count += 1
                
                except subprocess.TimeoutExpired:
                    logger.warning(f"   ⚠️  {script} (timeout)")
                    fail_count += 1
                except Exception as e:
                    logger.warning(f"   ⚠️  {script}: {e}")
                    fail_count += 1
        
        logger.info(f"\nValidation: {success_count} passed, {fail_count} warnings")
        return fail_count == 0
    
    def generate_compliance_report(self) -> Dict:
        """Generate comprehensive compliance report"""
        logger.info("\n" + "="*60)
        logger.info("README COMPLIANCE REPORT")
        logger.info("="*60)
        
        report = {
            'readme_files': len(self.readme_files),
            'python_scripts': len(self.python_scripts),
            'code_examples': len(self.code_examples),
            'missing_scripts': len(self.missing_scripts),
            'inconsistencies': len(self.inconsistencies),
            'status': 'PASS' if not self.missing_scripts else 'FAIL'
        }
        
        logger.info(f"\nREADME Files Checked: {report['readme_files']}")
        logger.info(f"Python Scripts Found: {report['python_scripts']}")
        logger.info(f"Code Examples Extracted: {report['code_examples']}")
        logger.info(f"Missing Scripts: {report['missing_scripts']}")
        logger.info(f"Inconsistencies: {report['inconsistencies']}")
        logger.info(f"\nStatus: {report['status']}")
        logger.info("="*60 + "\n")
        
        # Save report
        with open('compliance_report.json', 'w') as f:
            json.dump(report, f, indent=2)
        logger.info("Report saved to: compliance_report.json")
        
        return report
    
    def run_all_validations(self) -> bool:
        """Run all compliance checks"""
        logger.info("Starting README Compliance Validation\n")
        
        self.find_readme_files()
        self.find_python_scripts()
        self.extract_code_examples()
        
        checks = [
            self.validate_script_existence,
            self.check_argument_consistency,
            self.validate_help_output
        ]
        
        results = []
        for check in checks:
            try:
                results.append(check())
            except Exception as e:
                logger.error(f"Check {check.__name__} failed: {e}")
                results.append(False)
        
        self.generate_compliance_report()
        
        return all(results)

def main():
    parser = argparse.ArgumentParser(description='Validate README compliance')
    parser.add_argument('--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    validator = ReadmeComplianceValidator()
    success = validator.run_all_validations()
    
    return 0 if success else 1

if __name__ == '__main__':
    sys.exit(main())
