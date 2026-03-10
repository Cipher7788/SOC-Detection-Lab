#!/bin/bash

# SOC Lab Setup and Initialization Script

# Display the current date and time
echo "Starting SOC lab setup on $(date)"

# Update system packages
echo "Updating system packages..."
sudo apt-get update && sudo apt-get upgrade -y

# Install necessary tools
echo "Installing necessary tools..."
sudo apt-get install -y git curl

# Setup directory structure
mkdir -p ~/SOC_Lab/projects
mkdir -p ~/SOC_Lab/data

# Clone SOC Detection repository
echo "Cloning SOC Detection Lab repository..."
git clone https://github.com/Cipher7788/SOC-Detection-Lab.git ~/SOC_Lab/projects/SOC-Detection-Lab

# Additional setup tasks can be added here

# Script completion
echo "SOC lab setup completed on $(date)"