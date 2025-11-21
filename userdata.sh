#!/bin/bash

# Update package list
sudo apt-get update

# Install Apache2
sudo apt-get install -y apache2

# Print status
sudo systemctl status apache2