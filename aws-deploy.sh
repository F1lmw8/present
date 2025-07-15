#!/bin/bash

# AWS Deployment Pipeline Script
# Automated deployment for web applications to AWS S3 and CloudFront

set -e  # Exit on any error

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
PROJECT_NAME="warp-terminal-presentation"
S3_BUCKET="warp-presentation-bucket"
CLOUDFRONT_DISTRIBUTION_ID=""
AWS_REGION="us-east-1"
BUILD_DIR="./build"
DIST_DIR="./dist"

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if AWS CLI is installed
check_aws_cli() {
    if ! command -v aws &> /dev/null; then
        print_error "AWS CLI is not installed. Please install it first."
        echo "Installation guide: https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html"
        exit 1
    fi
    
    # Check if AWS credentials are configured
    if ! aws sts get-caller-identity &> /dev/null; then
        print_error "AWS credentials not configured. Please run 'aws configure' first."
        exit 1
    fi
    
    print_success "AWS CLI is configured and ready"
}

# Function to create build directory
prepare_build() {
    print_status "Preparing build directory..."
    
    # Create build directory
    mkdir -p $BUILD_DIR
    
    # Copy files to build directory
    if [ -f "warp-presentation.html" ]; then
        cp warp-presentation.html $BUILD_DIR/index.html
        print_success "Main presentation copied"
    fi
    
    if [ -f "landing-page.html" ]; then
        cp landing-page.html $BUILD_DIR/landing.html
        print_success "Landing page copied"
    fi
    
    # Create additional files for production
    cat > $BUILD_DIR/robots.txt << EOF
User-agent: *
Allow: /

Sitemap: https://$S3_BUCKET.s3-website-$AWS_REGION.amazonaws.com/sitemap.xml
EOF

    cat > $BUILD_DIR/sitemap.xml << EOF
<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
    <url>
        <loc>https://$S3_BUCKET.s3-website-$AWS_REGION.amazonaws.com/</loc>
        <lastmod>$(date -u +"%Y-%m-%dT%H:%M:%SZ")</lastmod>
        <changefreq>weekly</changefreq>
        <priority>1.0</priority>
    </url>
    <url>
        <loc>https://$S3_BUCKET.s3-website-$AWS_REGION.amazonaws.com/landing.html</loc>
        <lastmod>$(date -u +"%Y-%m-%dT%H:%M:%SZ")</lastmod>
        <changefreq>weekly</changefreq>
        <priority>0.8</priority>
    </url>
</urlset>
EOF

    print_success "Build directory prepared"
}

# Function to create S3 bucket
create_s3_bucket() {
    print_status "Setting up S3 bucket: $S3_BUCKET"
    
    # Check if bucket exists
    if aws s3api head-bucket --bucket "$S3_BUCKET" 2>/dev/null; then
        print_warning "S3 bucket already exists"
    else
        # Create bucket
        if [ "$AWS_REGION" = "us-east-1" ]; then
            aws s3api create-bucket --bucket "$S3_BUCKET" --region "$AWS_REGION"
        else
            aws s3api create-bucket --bucket "$S3_BUCKET" --region "$AWS_REGION" \
                --create-bucket-configuration LocationConstraint="$AWS_REGION"
        fi
        print_success "S3 bucket created"
    fi
    
    # Configure bucket for static website hosting
    aws s3 website s3://"$S3_BUCKET" --index-document index.html --error-document index.html
    
    # Set bucket policy for public read access
    cat > bucket-policy.json << EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "PublicReadGetObject",
            "Effect": "Allow",
            "Principal": "*",
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::$S3_BUCKET/*"
        }
    ]
}
EOF
    
    aws s3api put-bucket-policy --bucket "$S3_BUCKET" --policy file://bucket-policy.json
    rm bucket-policy.json
    
    print_success "S3 bucket configured for static website hosting"
}

# Function to deploy to S3
deploy_to_s3() {
    print_status "Deploying to S3..."
    
    # Sync files to S3
    aws s3 sync $BUILD_DIR s3://"$S3_BUCKET" --delete \
        --cache-control "max-age=31536000" \
        --exclude "*.html" \
        --exclude "*.xml" \
        --exclude "*.txt"
    
    # Upload HTML files with shorter cache time
    aws s3 sync $BUILD_DIR s3://"$S3_BUCKET" --delete \
        --cache-control "max-age=3600" \
        --include "*.html" \
        --include "*.xml" \
        --include "*.txt"
    
    # Set correct content types
    aws s3 cp s3://"$S3_BUCKET"/index.html s3://"$S3_BUCKET"/index.html \
        --content-type "text/html" --metadata-directive REPLACE
    
    aws s3 cp s3://"$S3_BUCKET"/landing.html s3://"$S3_BUCKET"/landing.html \
        --content-type "text/html" --metadata-directive REPLACE
    
    print_success "Files deployed to S3"
}

# Function to create CloudFront distribution
setup_cloudfront() {
    print_status "Setting up CloudFront distribution..."
    
    # Create CloudFront distribution configuration
    cat > cloudfront-config.json << EOF
{
    "CallerReference": "$PROJECT_NAME-$(date +%s)",
    "Comment": "CloudFront distribution for $PROJECT_NAME",
    "DefaultCacheBehavior": {
        "TargetOriginId": "S3-$S3_BUCKET",
        "ViewerProtocolPolicy": "redirect-to-https",
        "TrustedSigners": {
            "Enabled": false,
            "Quantity": 0
        },
        "ForwardedValues": {
            "QueryString": false,
            "Cookies": {
                "Forward": "none"
            }
        },
        "MinTTL": 0,
        "DefaultTTL": 86400,
        "MaxTTL": 31536000,
        "Compress": true
    },
    "Origins": {
        "Quantity": 1,
        "Items": [
            {
                "Id": "S3-$S3_BUCKET",
                "DomainName": "$S3_BUCKET.s3-website-$AWS_REGION.amazonaws.com",
                "CustomOriginConfig": {
                    "HTTPPort": 80,
                    "HTTPSPort": 443,
                    "OriginProtocolPolicy": "http-only"
                }
            }
        ]
    },
    "DefaultRootObject": "index.html",
    "Enabled": true,
    "PriceClass": "PriceClass_100"
}
EOF
    
    # Create distribution
    DISTRIBUTION_INFO=$(aws cloudfront create-distribution --distribution-config file://cloudfront-config.json)
    CLOUDFRONT_DISTRIBUTION_ID=$(echo $DISTRIBUTION_INFO | jq -r '.Distribution.Id')
    CLOUDFRONT_DOMAIN=$(echo $DISTRIBUTION_INFO | jq -r '.Distribution.DomainName')
    
    rm cloudfront-config.json
    
    print_success "CloudFront distribution created"
    print_status "Distribution ID: $CLOUDFRONT_DISTRIBUTION_ID"
    print_status "Domain: $CLOUDFRONT_DOMAIN"
    
    # Save distribution ID for future use
    echo $CLOUDFRONT_DISTRIBUTION_ID > .cloudfront-distribution-id
}

# Function to invalidate CloudFront cache
invalidate_cloudfront() {
    if [ -f ".cloudfront-distribution-id" ]; then
        CLOUDFRONT_DISTRIBUTION_ID=$(cat .cloudfront-distribution-id)
        print_status "Invalidating CloudFront cache..."
        
        aws cloudfront create-invalidation \
            --distribution-id $CLOUDFRONT_DISTRIBUTION_ID \
            --paths "/*"
        
        print_success "CloudFront cache invalidated"
    else
        print_warning "CloudFront distribution ID not found, skipping cache invalidation"
    fi
}

# Function to run security scan
run_security_scan() {
    print_status "Running security scan..."
    
    if [ -f "security-scanner.py" ]; then
        python3 security-scanner.py
        
        if [ $? -eq 0 ]; then
            print_success "Security scan passed"
        else
            print_warning "Security scan found issues, check the report"
        fi
    else
        print_warning "Security scanner not found, skipping security scan"
    fi
}

# Function to display deployment info
show_deployment_info() {
    print_success "🚀 Deployment Complete!"
    echo ""
    echo "📊 Deployment Summary:"
    echo "├── S3 Bucket: http://$S3_BUCKET.s3-website-$AWS_REGION.amazonaws.com"
    
    if [ -f ".cloudfront-distribution-id" ]; then
        CLOUDFRONT_DISTRIBUTION_ID=$(cat .cloudfront-distribution-id)
        echo "├── CloudFront ID: $CLOUDFRONT_DISTRIBUTION_ID"
        echo "└── CloudFront URL: https://$(aws cloudfront get-distribution --id $CLOUDFRONT_DISTRIBUTION_ID --query 'Distribution.DomainName' --output text)"
    else
        echo "└── CloudFront: Not configured"
    fi
    
    echo ""
    echo "🔧 Useful Commands:"
    echo "├── Update deployment: ./aws-deploy.sh"
    echo "├── Check status: aws s3 ls s3://$S3_BUCKET"
    echo "└── Delete resources: aws s3 rb s3://$S3_BUCKET --force"
}

# Main deployment function
main() {
    echo "🚀 AWS Deployment Pipeline for $PROJECT_NAME"
    echo "================================================"
    
    # Check prerequisites
    check_aws_cli
    
    # Prepare build
    prepare_build
    
    # Run security scan
    run_security_scan
    
    # Deploy to AWS
    create_s3_bucket
    deploy_to_s3
    
    # Setup CloudFront if not exists
    if [ ! -f ".cloudfront-distribution-id" ]; then
        setup_cloudfront
    else
        invalidate_cloudfront
    fi
    
    # Show deployment info
    show_deployment_info
    
    # Cleanup
    rm -rf $BUILD_DIR
    
    print_success "Deployment pipeline completed successfully!"
}

# Handle command line arguments
case "${1:-deploy}" in
    "deploy")
        main
        ;;
    "clean")
        print_status "Cleaning up AWS resources..."
        if [ -f ".cloudfront-distribution-id" ]; then
            CLOUDFRONT_DISTRIBUTION_ID=$(cat .cloudfront-distribution-id)
            aws cloudfront delete-distribution --id $CLOUDFRONT_DISTRIBUTION_ID --if-match $(aws cloudfront get-distribution --id $CLOUDFRONT_DISTRIBUTION_ID --query 'ETag' --output text)
            rm .cloudfront-distribution-id
        fi
        aws s3 rb s3://"$S3_BUCKET" --force
        print_success "AWS resources cleaned up"
        ;;
    "status")
        print_status "Checking deployment status..."
        aws s3 ls s3://"$S3_BUCKET"
        if [ -f ".cloudfront-distribution-id" ]; then
            CLOUDFRONT_DISTRIBUTION_ID=$(cat .cloudfront-distribution-id)
            aws cloudfront get-distribution --id $CLOUDFRONT_DISTRIBUTION_ID --query 'Distribution.Status' --output text
        fi
        ;;
    *)
        echo "Usage: $0 {deploy|clean|status}"
        echo "  deploy  - Deploy to AWS (default)"
        echo "  clean   - Remove AWS resources"
        echo "  status  - Check deployment status"
        exit 1
        ;;
esac
