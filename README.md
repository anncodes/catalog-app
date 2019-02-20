# Item Catalog Application
This application is developed for Udacity FSND project.  This app provides a list of places within a variety of categories as well as provide a user registration and authentication system.  Registered users will have the ability to post, edit and delete their own entries.

# Requirements
<ul>
	<li>Vagrant</li>
	<li>VirtualBox</li>
	<li>Google Dev Console</li>
</ul>

# Installation
<ol>
	<li>Install Vagrant and Virtual Box</li>
	<li>Clone repo https://github.com/anncodes/catalog-app.git</li>
	<li>Launch Vagrant VM by <code>vagrant up</code></li>
	<li>Log in Vagrant VM by <code>vagrant ssh</code></li>
	<li>Access shared files by <code>cd /vagrant</code></li>
	<li>Set up database <code>python database_setup.py</code></li>
	<li>Import data to database <code>python catalogdata.py</code></li>
	<li>Run application <code>python application.py</code></li>
	<li>Open application on browser <a href="http://localhost:5020">http://localhost:5020</a></li>
</ol>

