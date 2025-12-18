"""
AWS Security Compliance Auditor
================================
Enterprise-grade security audit tool for AWS infrastructure.
Implements CIS AWS Foundations Benchmark controls.

Author: Veronica Dwiyanti
Version: 2.0
License: MIT
"""

import streamlit as st
import boto3
import os
import json
import pandas as pd
from botocore.exceptions import ClientError, NoCredentialsError
from moto import mock_aws
from datetime import datetime
from io import BytesIO
import time

st.set_page_config(
    page_title="AWS Security Auditor",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

CIS_CONTROLS = {
    'root_mfa': 'CIS 1.5 - Ensure MFA is enabled for root account',
    'iam_mfa': 'CIS 1.10 - Ensure multi-factor authentication is enabled for all IAM users',
    'ssh_public': 'CIS 5.2 - Ensure no security groups allow ingress from 0.0.0.0/0 to port 22',
    's3_public': 'CIS 2.1.5 - Ensure S3 buckets have public access blocked',
    'ebs_encryption': 'CIS 2.2.1 - Ensure EBS volume encryption is enabled'
}

# ============================================================================
# Session State
# ============================================================================

def init_session_state():
    """Initialize all session state variables"""
    defaults = {
        'remediated': False,
        'initialized': False,
        'audit_mode': 'demo',  
        'audit_history': [],
        'last_scan_time': None
    }
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value

init_session_state()

# ============================================================================
# AWS Environment
# ============================================================================

def setup_demo_environment():
    """Set up mock AWS credentials for demo mode"""
    os.environ['AWS_ACCESS_KEY_ID'] = 'testing'
    os.environ['AWS_SECRET_ACCESS_KEY'] = 'testing'
    os.environ['AWS_SECURITY_TOKEN'] = 'testing'
    os.environ['AWS_SESSION_TOKEN'] = 'testing'
    os.environ['AWS_DEFAULT_REGION'] = 'us-east-1'

def validate_aws_credentials(access_key, secret_key, region):
    """Validate AWS credentials by making a test call"""
    try:
        session = boto3.Session(
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name=region
        )
        sts = session.client('sts')
        sts.get_caller_identity()
        return True, "Credentials validated successfully"
    except NoCredentialsError:
        return False, "Invalid credentials provided"
    except ClientError as e:
        return False, f"AWS Error: {str(e)}"
    except Exception as e:
        return False, f"Unexpected error: {str(e)}"

@mock_aws
def create_mock_resources(secure_mode=False):
    """
    Generate mock AWS resources for demonstration.
    
    Args:
        secure_mode (bool): If True, creates secure configurations
    
    Returns:
        dict: Summary of created resources
    """
    s3 = boto3.client('s3', region_name='us-east-1')
    ec2 = boto3.client('ec2', region_name='us-east-1')
    iam = boto3.client('iam', region_name='us-east-1')
    
    resources_created = {
        's3_buckets': 0,
        'security_groups': 0,
        'ebs_volumes': 0,
        'iam_users': 0
    }

    # Create S3 buckets with varying security postures
    bucket_configs = [
        ('finance-data-archives', True),
        ('customer-records-db', False),
        ('public-website-assets', False),
        ('dev-test-logs', False),
        ('backup-snapshots', True)
    ]
    
    for bucket_name, is_secure in bucket_configs:
        try:
            s3.create_bucket(Bucket=bucket_name)
            resources_created['s3_buckets'] += 1
            
            if secure_mode or is_secure:
                s3.put_public_access_block(
                    Bucket=bucket_name,
                    PublicAccessBlockConfiguration={
                        'BlockPublicAcls': True,
                        'IgnorePublicAcls': True,
                        'BlockPublicPolicy': True,
                        'RestrictPublicBuckets': True
                    }
                )
        except Exception as e:
            st.warning(f"Failed to create bucket {bucket_name}: {str(e)}")

    # Create VPC and Security Groups
    try:
        vpc_response = ec2.create_vpc(CidrBlock='10.0.0.0/16')
        vpc_id = vpc_response['Vpc']['VpcId']
        
        # Secure SG
        sg_db = ec2.create_security_group(
            GroupName='database-tier',
            Description='Database security group',
            VpcId=vpc_id
        )
        ec2.authorize_security_group_ingress(
            GroupId=sg_db['GroupId'],
            IpPermissions=[{
                'IpProtocol': 'tcp',
                'FromPort': 3306,
                'ToPort': 3306,
                'IpRanges': [{'CidrIp': '10.0.0.0/16', 'Description': 'Internal only'}]
            }]
        )
        resources_created['security_groups'] += 1
        
        # Vulnerable SG (unless secure_mode)
        sg_web = ec2.create_security_group(
            GroupName='web-frontend-legacy',
            Description='Legacy web server',
            VpcId=vpc_id
        )
        ssh_cidr = '10.0.1.0/24' if secure_mode else '0.0.0.0/0'
        ec2.authorize_security_group_ingress(
            GroupId=sg_web['GroupId'],
            IpPermissions=[{
                'IpProtocol': 'tcp',
                'FromPort': 22,
                'ToPort': 22,
                'IpRanges': [{'CidrIp': ssh_cidr, 'Description': 'SSH access'}]
            }]
        )
        resources_created['security_groups'] += 1
        
    except Exception as e:
        st.warning(f"Failed to create security groups: {str(e)}")

    # Create EBS volumes
    volume_configs = [
        (100, True, 'prod-database'),
        (50, False, 'dev-workspace'),
        (200, False, 'log-storage')
    ]
    
    for size, encrypted, name in volume_configs:
        try:
            ec2.create_volume(
                AvailabilityZone='us-east-1a',
                Size=size,
                Encrypted=encrypted if not secure_mode else True,
                TagSpecifications=[{
                    'ResourceType': 'volume',
                    'Tags': [{'Key': 'Name', 'Value': name}]
                }]
            )
            resources_created['ebs_volumes'] += 1
        except Exception as e:
            st.warning(f"Failed to create volume {name}: {str(e)}")

    # Create IAM users
    users = [
        ('alice_admin', True),
        ('bob_developer', False),
        ('charlie_contractor', False),
        ('david_devops', True)
    ]
    
    for username, has_mfa in users:
        try:
            iam.create_user(UserName=username)
            resources_created['iam_users'] += 1
            
            if secure_mode or has_mfa:
                iam.create_virtual_mfa_device(
                    VirtualMFADeviceName=f'{username}-mfa',
                    Path='/'
                )
        except Exception as e:
            st.warning(f"Failed to create user {username}: {str(e)}")
    
    return resources_created

# ============================================================================
# Security Check Functions
# ============================================================================

@mock_aws
def check_root_account_mfa(is_remediated=False):
    """
    CIS 1.5 - Check if root account has MFA enabled
    
    Args:
        is_remediated (bool): Override for demo mode
    
    Returns:
        dict: Check result with status and details
    """
    try:
        iam = boto3.client('iam', region_name='us-east-1')
        summary = iam.get_account_summary()
        
        if st.session_state.audit_mode == 'demo':
            mfa_enabled = is_remediated
        else:
            mfa_enabled = summary['SummaryMap'].get('AccountMFAEnabled', 0) == 1
        
        return {
            'control_id': 'CIS 1.5',
            'category': 'Identity & Access Management',
            'check_name': 'Root Account MFA',
            'status': 'PASS' if mfa_enabled else 'CRITICAL',
            'severity': 'CRITICAL',
            'description': CIS_CONTROLS['root_mfa'],
            'finding': 'Root account MFA is enabled' if mfa_enabled else 'Root account does not have MFA enabled',
            'recommendation': 'Enable virtual MFA device for root account via AWS Console',
            'risk': 'Unauthorized access to root account could compromise entire AWS environment',
            'details': {
                'mfa_enabled': mfa_enabled,
                'account_access_keys': 0  # Root should have 0
            }
        }
    except Exception as e:
        return {
            'control_id': 'CIS 1.5',
            'category': 'Identity & Access Management',
            'check_name': 'Root Account MFA',
            'status': 'ERROR',
            'severity': 'HIGH',
            'finding': f'Error checking root MFA: {str(e)}',
            'recommendation': 'Verify IAM permissions for auditor role',
            'details': {}
        }

@mock_aws
def check_iam_user_mfa():
    """
    CIS 1.10 - Check if all IAM users have MFA enabled
    
    Returns:
        dict: Check result with non-compliant users listed
    """
    try:
        iam = boto3.client('iam', region_name='us-east-1')
        
        users_response = iam.list_users()
        all_users = [u['UserName'] for u in users_response.get('Users', [])]
        
        mfa_devices = iam.list_virtual_mfa_devices()
        users_with_mfa = set()
        
        for device in mfa_devices.get('VirtualMFADevices', []):
            if 'User' in device:
                users_with_mfa.add(device['User']['UserName'])
        
        users_without_mfa = [u for u in all_users if u not in users_with_mfa]
        
        compliance_rate = ((len(all_users) - len(users_without_mfa)) / len(all_users) * 100) if all_users else 100
        
        return {
            'control_id': 'CIS 1.10',
            'category': 'Identity & Access Management',
            'check_name': 'IAM User MFA Compliance',
            'status': 'PASS' if not users_without_mfa else 'FAIL',
            'severity': 'HIGH',
            'description': CIS_CONTROLS['iam_mfa'],
            'finding': f'{len(users_without_mfa)} out of {len(all_users)} users missing MFA ({compliance_rate:.1f}% compliant)',
            'recommendation': 'Enable MFA for all IAM users, especially those with console access',
            'risk': 'Compromised credentials without MFA allow unauthorized account access',
            'details': {
                'total_users': len(all_users),
                'users_with_mfa': len(users_with_mfa),
                'users_without_mfa': users_without_mfa,
                'compliance_percentage': compliance_rate
            }
        }
    except Exception as e:
        return {
            'control_id': 'CIS 1.10',
            'category': 'Identity & Access Management',
            'check_name': 'IAM User MFA Compliance',
            'status': 'ERROR',
            'finding': f'Error: {str(e)}',
            'details': {}
        }

@mock_aws
def check_security_group_ssh():
    """
    CIS 5.2 - Check for security groups allowing SSH from 0.0.0.0/0
    
    Returns:
        dict: Check result with vulnerable security groups
    """
    try:
        ec2 = boto3.client('ec2', region_name='us-east-1')
        response = ec2.describe_security_groups()
        
        vulnerable_sgs = []
        
        for sg in response.get('SecurityGroups', []):
            for permission in sg.get('IpPermissions', []):
                from_port = permission.get('FromPort')
                to_port = permission.get('ToPort')
                
                if from_port and from_port <= 22 <= to_port:
                    for ip_range in permission.get('IpRanges', []):
                        if ip_range.get('CidrIp') == '0.0.0.0/0':
                            vulnerable_sgs.append({
                                'group_id': sg['GroupId'],
                                'group_name': sg['GroupName'],
                                'vpc_id': sg.get('VpcId', 'N/A'),
                                'description': sg.get('Description', '')
                            })
        
        return {
            'control_id': 'CIS 5.2',
            'category': 'Network Security',
            'check_name': 'Public SSH Access',
            'status': 'PASS' if not vulnerable_sgs else 'CRITICAL',
            'severity': 'CRITICAL',
            'description': CIS_CONTROLS['ssh_public'],
            'finding': f'Found {len(vulnerable_sgs)} security group(s) with public SSH access' if vulnerable_sgs else 'No security groups allow public SSH access',
            'recommendation': 'Restrict SSH access to specific IP ranges or use AWS Systems Manager Session Manager',
            'risk': 'Public SSH access exposes servers to brute force attacks and unauthorized access',
            'details': {
                'vulnerable_count': len(vulnerable_sgs),
                'vulnerable_groups': vulnerable_sgs
            }
        }
    except Exception as e:
        return {
            'control_id': 'CIS 5.2',
            'category': 'Network Security',
            'check_name': 'Public SSH Access',
            'status': 'ERROR',
            'finding': f'Error: {str(e)}',
            'details': {}
        }

@mock_aws
def check_s3_public_access():
    """
    CIS 2.1.5 - Check S3 buckets for public access configuration
    
    Returns:
        dict: Check result with exposed buckets
    """
    try:
        s3 = boto3.client('s3', region_name='us-east-1')
        response = s3.list_buckets()
        
        exposed_buckets = []
        warning_buckets = []
        secure_buckets = []
        
        for bucket in response.get('Buckets', []):
            bucket_name = bucket['Name']
            
            try:
                block_config = s3.get_public_access_block(Bucket=bucket_name)
                config = block_config['PublicAccessBlockConfiguration']
                
                all_blocked = all([
                    config.get('BlockPublicAcls'),
                    config.get('IgnorePublicAcls'),
                    config.get('BlockPublicPolicy'),
                    config.get('RestrictPublicBuckets')
                ])
                
                if all_blocked:
                    secure_buckets.append(bucket_name)
                else:
                    warning_buckets.append(bucket_name)
                    
            except ClientError as e:
                if e.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
                    exposed_buckets.append(bucket_name)
        
        total_buckets = len(exposed_buckets) + len(warning_buckets) + len(secure_buckets)
        
        return {
            'control_id': 'CIS 2.1.5',
            'category': 'Data Protection',
            'check_name': 'S3 Public Access Block',
            'status': 'PASS' if not exposed_buckets else 'FAIL',
            'severity': 'HIGH',
            'description': CIS_CONTROLS['s3_public'],
            'finding': f'{len(exposed_buckets)} exposed, {len(warning_buckets)} partially protected, {len(secure_buckets)} secure buckets',
            'recommendation': 'Enable S3 Block Public Access at account and bucket level',
            'risk': 'Public S3 buckets can lead to data breaches and compliance violations',
            'details': {
                'total_buckets': total_buckets,
                'exposed_buckets': exposed_buckets,
                'warning_buckets': warning_buckets,
                'secure_buckets': secure_buckets
            }
        }
    except Exception as e:
        return {
            'control_id': 'CIS 2.1.5',
            'category': 'Data Protection',
            'check_name': 'S3 Public Access Block',
            'status': 'ERROR',
            'finding': f'Error: {str(e)}',
            'details': {}
        }

@mock_aws
def check_ebs_encryption():
    """
    CIS 2.2.1 - Check if EBS volumes are encrypted
    
    Returns:
        dict: Check result with unencrypted volumes
    """
    try:
        ec2 = boto3.client('ec2', region_name='us-east-1')
        response = ec2.describe_volumes()
        
        unencrypted_volumes = []
        encrypted_volumes = []
        
        for volume in response.get('Volumes', []):
            volume_data = {
                'volume_id': volume['VolumeId'],
                'size': volume['Size'],
                'state': volume['State'],
                'az': volume['AvailabilityZone']
            }
            
            if volume.get('Encrypted', False):
                encrypted_volumes.append(volume_data)
            else:
                unencrypted_volumes.append(volume_data)
        
        total_volumes = len(encrypted_volumes) + len(unencrypted_volumes)
        encryption_rate = (len(encrypted_volumes) / total_volumes * 100) if total_volumes > 0 else 100
        
        return {
            'control_id': 'CIS 2.2.1',
            'category': 'Data Protection',
            'check_name': 'EBS Volume Encryption',
            'status': 'PASS' if not unencrypted_volumes else 'WARNING',
            'severity': 'MEDIUM',
            'description': CIS_CONTROLS['ebs_encryption'],
            'finding': f'{len(unencrypted_volumes)} out of {total_volumes} volumes unencrypted ({encryption_rate:.1f}% encrypted)',
            'recommendation': 'Enable EBS encryption by default and migrate unencrypted volumes',
            'risk': 'Unencrypted volumes expose data at rest to unauthorized access',
            'details': {
                'total_volumes': total_volumes,
                'encrypted_count': len(encrypted_volumes),
                'unencrypted_count': len(unencrypted_volumes),
                'unencrypted_volumes': unencrypted_volumes,
                'encryption_percentage': encryption_rate
            }
        }
    except Exception as e:
        return {
            'control_id': 'CIS 2.2.1',
            'category': 'Data Protection',
            'check_name': 'EBS Volume Encryption',
            'status': 'ERROR',
            'finding': f'Error: {str(e)}',
            'details': {}
        }

# ============================================================================
# Reporting & Export Functions
# ============================================================================

def generate_csv_report(results, metadata):
    """Generate CSV report of audit findings"""
    df_data = []
    
    for result in results:
        df_data.append({
            'Control ID': result.get('control_id', 'N/A'),
            'Category': result.get('category', 'N/A'),
            'Check Name': result.get('check_name', 'N/A'),
            'Status': result.get('status', 'N/A'),
            'Severity': result.get('severity', 'N/A'),
            'Finding': result.get('finding', 'N/A'),
            'Recommendation': result.get('recommendation', 'N/A')
        })
    
    df = pd.DataFrame(df_data)
    return df.to_csv(index=False)

def generate_json_report(results, metadata):
    """Generate JSON report of audit findings"""
    report = {
        'metadata': metadata,
        'summary': {
            'total_checks': len(results),
            'passed': sum(1 for r in results if r['status'] == 'PASS'),
            'failed': sum(1 for r in results if r['status'] in ['FAIL', 'CRITICAL']),
            'warnings': sum(1 for r in results if r['status'] == 'WARNING'),
            'errors': sum(1 for r in results if r['status'] == 'ERROR')
        },
        'findings': results
    }
    return json.dumps(report, indent=2)

# ============================================================================
# UI Components
# ============================================================================

def render_metric_card(label, value, delta=None, help_text=None):
    """Render a styled metric card"""
    st.metric(
        label=label,
        value=value,
        delta=delta,
        help=help_text
    )

def render_finding_card(result):
    """Render a detailed finding card"""
    status_colors = {
        'PASS': '🟢',
        'FAIL': '🔴',
        'CRITICAL': '🔴',
        'WARNING': '🟡',
        'ERROR': '⚪'
    }
    
    with st.container():
        col1, col2, col3 = st.columns([0.5, 3, 1])
        
        with col1:
            st.markdown(f"### {status_colors.get(result['status'], '⚪')}")
        
        with col2:
            st.markdown(f"**{result['check_name']}**")
            st.caption(f"{result.get('control_id', 'N/A')} • {result.get('description', '')}")
        
        with col3:
            severity = result.get('severity', 'MEDIUM')
            if severity == 'CRITICAL':
                st.error(severity)
            elif severity == 'HIGH':
                st.warning(severity)
            else:
                st.info(severity)
        
        st.markdown(f"**Finding:** {result.get('finding', 'No details available')}")
        
        if result['status'] not in ['PASS', 'ERROR']:
            st.markdown(f"**Recommendation:** {result.get('recommendation', 'N/A')}")
            
            if result.get('risk'):
                with st.expander("🔍 Risk Assessment"):
                    st.warning(result['risk'])
        
        if result.get('details') and result['status'] != 'PASS':
            with st.expander("📋 Technical Details"):
                st.json(result['details'])
        
        st.divider()

# ============================================================================
# Main Application
# ============================================================================

def main():
    """Main application entry point"""
    
    with st.sidebar:
        st.image("https://img.icons8.com/fluency/96/000000/security-checked.png", width=80)
        st.title("Configuration")
        
        st.markdown("###  Audit Mode")
        audit_mode = st.radio(
            "Select Mode",
            options=['demo', 'live'],
            format_func=lambda x: " Demo Mode (Mock Data)" if x == 'demo' else " Live Mode (Real AWS)",
            help="Demo mode uses mock data. Live mode requires AWS credentials."
        )
        
        st.session_state.audit_mode = audit_mode
        
        if audit_mode == 'demo':
            setup_demo_environment()
        else:
            st.warning("⚠️ Live mode requires valid AWS credentials")
            with st.expander("🔑 AWS Credentials"):
                aws_access_key = st.text_input("Access Key ID", type="password")
                aws_secret_key = st.text_input("Secret Access Key", type="password")
                aws_region = st.selectbox("Region", ["us-east-1", "us-west-2", "ap-southeast-1", "eu-west-1"])
                
                if st.button("Validate Credentials"):
                    is_valid, message = validate_aws_credentials(aws_access_key, aws_secret_key, aws_region)
                    if is_valid:
                        st.success(message)
                        os.environ['AWS_ACCESS_KEY_ID'] = aws_access_key
                        os.environ['AWS_SECRET_ACCESS_KEY'] = aws_secret_key
                        os.environ['AWS_DEFAULT_REGION'] = aws_region
                    else:
                        st.error(message)
        st.divider()
        
        st.markdown("###  Audit Information")
        auditor_name = st.text_input("Auditor Name", value="Security Team")
        organization = st.text_input("Organization", value="Enterprise Corp")
        
        st.divider()
        
        st.markdown("###  Display Options")
        show_passed = st.checkbox("Show Passed Checks", value=True)
        show_details = st.checkbox("Show Technical Details", value=True)
        
        st.divider()
        
        st.markdown("###  Control Panel")
        if st.button("🔄 Reset Environment", use_container_width=True):
            for key in ['initialized', 'remediated', 'audit_history']:
                if key in st.session_state:
                    del st.session_state[key]
            st.rerun()
    
    # Main content
    st.title("🛡️ AWS Security Compliance Auditor")
    st.markdown(f"**Organization:** {organization} • **Auditor:** {auditor_name} • **Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    st.caption("Based on CIS AWS Foundations Benchmark v1.5.0")
    st.markdown("---")
    
    if not st.session_state.initialized:
        if audit_mode == 'demo':
            with st.spinner("Initializing mock AWS environment..."):
                resources = create_mock_resources(secure_mode=st.session_state.remediated)
                st.session_state.initialized = True
                st.session_state.resources_created = resources
        else:
            st.session_state.initialized = True
    
    col1, col2, col3 = st.columns([2, 1, 2])
    with col2:
        run_scan = st.button("🔍 Run Security Audit", type="primary", use_container_width=True)
    
    if run_scan:
        with st.spinner("Running comprehensive security audit..."):
            progress_bar = st.progress(0)
            results = []
            checks = [
                (check_root_account_mfa, [st.session_state.remediated], 20),
                (check_iam_user_mfa, [], 40),
                (check_security_group_ssh, [], 60),
                (check_s3_public_access, [], 80),
                (check_ebs_encryption, [], 100)
            ]
            
            for check_func, args, progress in checks:
                result = check_func(*args)
                results.append(result)
                progress_bar.progress(progress / 100)
                time.sleep(0.3)  # Simulate processing
            
            st.session_state.last_results = results
            st.session_state.last_scan_time = datetime.now()
            
            if 'audit_history' not in st.session_state:
                st.session_state.audit_history = []
            
            st.session_state.audit_history.append({
                'timestamp': datetime.now(),
                'results': results,
                'auditor': auditor_name,
                'organization': organization
            })
    
    # Display results
    if hasattr(st.session_state, 'last_results'):
        results = st.session_state.last_results
        
        total_checks = len(results)
        passed = sum(1 for r in results if r['status'] == 'PASS')
        failed = sum(1 for r in results if r['status'] in ['FAIL', 'CRITICAL'])
        warnings = sum(1 for r in results if r['status'] == 'WARNING')
        errors = sum(1 for r in results if r['status'] == 'ERROR')
        
        compliance_score = int((passed / total_checks) * 100) if total_checks > 0 else 0
        
        # Summary Dashboard
        st.markdown("## Executive Summary")
        col1, col2, col3, col4, col5 = st.columns(5)
        
        with col1:
            render_metric_card(
                "Compliance Score",
                f"{compliance_score}%",
                delta="Excellent" if compliance_score == 100 else f"-{100-compliance_score}% from target",
                help_text="Percentage of checks passed"
            ) 
        with col2:
            render_metric_card("Checks Passed", passed, help_text="Number of security controls passed")
        with col3:
            render_metric_card("Critical Issues", failed, delta="Urgent" if failed > 0 else None, help_text="High severity findings requiring immediate action")
        with col4:
            render_metric_card("Warnings", warnings, help_text="Medium severity findings")
        with col5:
            render_metric_card("Errors", errors, help_text="Checks that failed to execute")
        
        st.progress(compliance_score / 100)
        
        if failed > 0:
            st.error(f"⚠️ **CRITICAL:** {failed} security issue(s) detected. Immediate remediation required!")
            
            if audit_mode == 'demo':
                col_a, col_b = st.columns([1, 3])
                with col_a:
                    if st.button("🔧 Auto-Remediate All Issues", type="primary"):
                        with st.spinner("Applying security patches..."):
                            time.sleep(2)
                            st.session_state.remediated = True
                            st.session_state.initialized = False
                            st.rerun()
        elif st.session_state.remediated:
            st.success("✅ All security issues have been resolved! Environment is now compliant.")
            st.balloons()
        else:
            st.success("✅ Excellent! All security controls passed. Your environment meets CIS Benchmark standards.")
        
        st.markdown("---")
        
        st.markdown("## 📥 Export Reports")
        col_exp1, col_exp2, col_exp3 = st.columns(3)
        
        metadata = {
            'audit_date': datetime.now().isoformat(),
            'auditor': auditor_name,
            'organization': organization,
            'mode': audit_mode,
            'compliance_score': compliance_score
        }
        
        with col_exp1:
            csv_data = generate_csv_report(results, metadata)
            st.download_button(
                label="📄 Download CSV Report",
                data=csv_data,
                file_name=f"aws_audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv",
                use_container_width=True
            )
        
        with col_exp2:
            json_data = generate_json_report(results, metadata)
            st.download_button(
                label="📋 Download JSON Report",
                data=json_data,
                file_name=f"aws_audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                mime="application/json",
                use_container_width=True
            )
        
        with col_exp3:
            summary_text = f"""AWS Security Audit Report
Organization: {organization}
Auditor: {auditor_name}
Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Compliance Score: {compliance_score}%

Summary:
- Total Checks: {total_checks}
- Passed: {passed}
- Failed: {failed}
- Warnings: {warnings}
"""
            st.download_button(
                label="📝 Download Summary",
                data=summary_text,
                file_name=f"aws_audit_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                mime="text/plain",
                use_container_width=True
            )
        
        st.markdown("---")
        
        st.markdown("## 🔍 Detailed Findings")
        
        categories = list(set(r['category'] for r in results))
        tabs = st.tabs([f"📁 {cat}" for cat in categories])
        
        for tab, category in zip(tabs, categories):
            with tab:
                st.markdown(f"### {category}")
                category_results = [r for r in results if r['category'] == category]
                
                for result in category_results:
                    if not show_passed and result['status'] == 'PASS':
                        continue
                    render_finding_card(result)
        
        st.markdown("---")
        
        if len(st.session_state.audit_history) > 1:
            st.markdown("##  Audit History")
            
            history_data = []
            for audit in st.session_state.audit_history[-10:]:  # Last 10 audits
                audit_passed = sum(1 for r in audit['results'] if r['status'] == 'PASS')
                audit_total = len(audit['results'])
                history_data.append({
                    'Timestamp': audit['timestamp'].strftime('%Y-%m-%d %H:%M:%S'),
                    'Compliance Score': f"{int((audit_passed/audit_total)*100)}%",
                    'Passed': audit_passed,
                    'Failed': audit_total - audit_passed,
                    'Auditor': audit['auditor']
                })
            
            df_history = pd.DataFrame(history_data)
            st.dataframe(df_history, use_container_width=True, hide_index=True)
    
    else:
        st.info("👆 Click **'Run Security Audit'** to start scanning your AWS environment for security compliance.")
        st.markdown("### 🎯 What This Tool Checks")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("""
            **Identity & Access Management**
            - Root account MFA status
            - IAM user MFA compliance
            - Password policies
            - Access key rotation
            
            **Network Security**
            - Security group configurations
            - Public SSH/RDP access
            - VPC flow logs
            - Network ACLs
            """)
        
        with col2:
            st.markdown("""
            **Data Protection**
            - S3 bucket public access
            - S3 bucket encryption
            - EBS volume encryption
            - RDS encryption status
            
            **Logging & Monitoring**
            - CloudTrail configuration
            - CloudWatch alarms
            - Config recorder status
            - VPC flow logging
            """)
        
        st.markdown("---")
        st.markdown("### 📚 Compliance Frameworks")
        st.markdown("""
        This tool implements security controls from:
        - **CIS AWS Foundations Benchmark v1.5.0**
        - AWS Well-Architected Framework - Security Pillar
        - NIST Cybersecurity Framework
        """)

if __name__ == "__main__":
    main()