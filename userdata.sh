#!/bin/bash
set -e

# 1. Update and Install Dependencies
apt-get update -y
apt-get install -y apache2 php libapache2-mod-php php-mysql mariadb-client git stress-ng jq unzip

# 2. Install AWS CLI v2
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
./aws/install

# 3. Start and Enable Apache
systemctl start apache2
systemctl enable apache2

# 4. Configure Apache to prioritize index.php
sed -i 's/DirectoryIndex index.html index.cgi index.pl index.php/DirectoryIndex index.php index.html index.cgi index.pl/g' /etc/apache2/mods-enabled/dir.conf
systemctl restart apache2

# 5. Fetch Database Credentials from Secrets Manager
SECRET_JSON=$(aws secretsmanager get-secret-value --secret-id ${secret_name} --region ${region} --query SecretString --output text)
DB_USER=$(echo $SECRET_JSON | jq -r .username)
DB_PASS=$(echo $SECRET_JSON | jq -r .password)

# 6. Deploy Application Code
cd /var/www/html
rm -rf * 

git clone https://github.com/edaviage/818N-E_Commerce_Application.git temp_repo
mv temp_repo/* .
mv temp_repo/.htaccess . 2>/dev/null || true # Move hidden files if any
rm -rf temp_repo

# 7. Configure Database Connection 
cat <<EOF > includes/connect.php
<?php
\$con = new mysqli('${db_endpoint}', '\$DB_USER', '\$DB_PASS', '${db_name}');

if(!\$con){
    die(mysqli_error(\$con));
}
?>
EOF

# 8. Initialize Database
if [ -f "Database/ecommerce_1.sql" ]; then
    echo "Running database initialization..."
    mysql -h ${db_endpoint} -u "$DB_USER" -p"$DB_PASS" ${db_name} < Database/ecommerce_1.sql
    echo "Database initialized."
else
    echo "SQL file not found at Database/ecommerce_1.sql, skipping initialization."
fi

# 9. Set Permissions
chown -R www-data:www-data /var/www/html
chmod -R 755 /var/www/html

echo "Userdata script completed successfully."
