# Flask_Template
A Flask template for your web application ideas. This is a simple Flask web application that you can customize.  
This template web application features the following pages:  
- Home Page
- Support Page
- Profile Page
- Registration Page
- Login Page
- Two-Factor Setup Page
- Variable session timeout

Other functional features include:
- Login Required Pages
- No-Login Required Pages
- Multifactor Authentication Required Pages
- Self-Service User Profile Updates
- Self-Service Password Reset

## How to setup on PythonAnywhere
1. Create new Web App
2. Select Flask
3. Select Python 3.10 (Flask 2.1.2)
4. Ensure the path is correct e.g. /home/{your user name}/{your app name}/flask_app.py
5. Upload these files into the newly created directory from the previous step e.g. /home/{your user name}/{your app name}
6. Create a virtual environment e.g. mkvirtualenv {your app name} --python=/usr/bin/python3.10 https://help.pythonanywhere.com/pages/VirtualEnvForWebsites
7. Install the requirements package e.g. pip install -r /home/{your user name}/{your app name}/requirements.txt
8. Update your web app to use the virtual environment e.g. /home/{your user name}/.virtualenvs/{your app name}
9. Update the ".env" file with your information **You MUST change these values to ensure your site is safe
-- Placeholder
11. Reload your Web App
