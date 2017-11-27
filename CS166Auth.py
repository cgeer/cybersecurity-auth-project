#Connor Geer
#CS 166
#Program that takes a username and password and allows access to certain menu
#items based on user's access level
#----------------------------------------------------------------------------
#To test: Run in python shell, create account first
#Encryption Algorithm: Takes each char in the string, and adds five to it's 
#ASCII value
import sys
import re
import secrets
import hashlib

def main():

    #try:

        #Opens authorization file
        auth = open('CS166Auth.csv', 'r')

        #Read all lines from file
        users = auth.readlines()

        #Close file
        auth.close()

        #Send to initial menu
        topMenu = int(input("Top Menu Options:\n1)Log In\n2)Create Account\n3)Quit\n"))
        if topMenu == 3:
            sys.exit(0)
        elif topMenu == 2:
            users = createAccount()

        #Strip newline character from each line
        index = 0
        while index < len(users):
            users[index] = users[index].rstrip('\n')
            index += 1
                    
        #Loops until input matches a username and password
        authorized = 0;
        while(authorized != 1):

            #Have user input username
            name = str(input("Enter username: "))

            #Have user input password
            password = str(input("Enter password: "))

            #Split lines into [user, password, access level, salt] and check input against
            #users in database
            index = 0
            for line in users:
                credentials = line.split(',')
                encryptMe = password + credentials[3]
                sha = hashlib.sha512()
                sha.update(encryptMe.encode('utf-8'))
                encrypted = sha.hexdigest()
                    
                if credentials[0] == name and credentials[1] == encrypted:
                    print("Access granted. Access level: ", credentials[2], sep = '')
                    access = credentials[2]
                    authorized = 1;
                    break

            #If credentials are incorrect, gives user a choice to try again
            if authorized == 0:
                tryAgain = int(input("Incorrect username or password. Menu Options:\n1)Try Again\n2)Create Account\n3)Quit\n"))
                if tryAgain == 3:
                    sys.exit(0)
                elif tryAgain == 2:
                    users = createAccount()

        #If credentials are correct, user is brought to home page
        choice = homePage()

        #Direct users based on choice and access level
        #Access Levels: 1 - Admin; 2 - Employee; 3 - Customer
        while choice != 0:

            #Send to My Account page
            if choice == 1:
                print("You have accessed your Account page.", end = '\n')
                backToHome = str(input("Would you like to select another option? (y or n): "))
                if backToHome == 'n':
                    break
                else:
                    choice = homePage()

            #Send to Finances page, access level: Employee, Admin
            if choice == 2 and (access == 2 or access == 1):
                print("You have accessed the Finances page.", end = '\n')
                backToHome = str(input("Would you like to select another option? (y or n): "))
                if backToHome == 'n':
                    break
                else:
                    choice = homePage()

            elif choice == 2 and (access == 3):
                print("You do not have access to this page.", end = '\n')
                backToHome = str(input("Would you like to select another option? (y or n): "))
                if backToHome == 'n':
                    break
                else:
                    choice = homePage()

            #Send to Site Maintenance page, access level: Admin
            if choice == 3 and (access == 1):
                print("You have accessed the Site Maintenance page.")
                backToHome = str(input("Would you like to select another option? (y or n): "))
                if backToHome == 'n':
                    break
                else:
                    choice = homePage()

            elif choice == 3 and (ac2cess == 3 or access == 2):
                print("You do not have access to this page.", end = '\n')
                backToHome = str(input("Would you like to select another option? (y or n): "))
                if backToHome == 'n':
                    break
                else:
                    choice = homePage()

        print("You have successfully logged out.", end = '\n')

##    except IOError:
##        print('Cannot find one or both requested files,')
##    except ValueError:
##        print('Unexpected value.')
##    except:
##        print('An unexpected error occurred')    


def createAccount():

    #Open auth file
    file = open('CS166Auth.csv', 'a')

    #Create username
    user = str(input("Create username: "))
    user = user + ","

    #Write username to file
    file.write(user)

    #Enter password creation loop and only exit if password is valid
    valid = 0
    while valid == 0:
               
        password = str(input("Create password (Must be between 8 - 25 characters and have one letter and one number): "))
        hasLetter = re.findall('[a-zA-Z]', password)
        hasNumber = re.findall('[0-9]', password)

        if len(hasNumber) == 0 or len(hasLetter) == 0 or len(password) > 25 or len(password) < 8:
            print("Invalid password. Must be between 8 - 15 characters and have one letter and one number")
        else:
            valid = 1                             

    #Create salt
    salt = secrets.token_hex(16)
    print("Salt: ", salt)

    #Add salt
    password += salt
    
    #Encrypt password
    enc = hashlib.sha512()
    enc.update(password.encode('utf-8'))
    encrypted = enc.hexdigest()

    #Write salted/encrypted password, access level, and salt to file
    encrypted = encrypted + ","
    file.write(encrypted)
    file.write('3,')
    file.write(salt)
    file.write('\n')

    #Success message
    print("Credentials saved!", end = '\n')

    #Closes 
    file.close()

    #Open auth file to be read
    file = open('CS166Auth.csv', 'r')

    #Read all lines from file
    users = file.readlines()

    #Close file
    file.close()

    #Return updated credential list
    return users

def homePage():

    print("Welcome to Company Home Page.", end = '\n')
    print("1. My Account", end = '\n')
    print("2. Finances", end = '\n')
    print("3. Site Maintenance", end = '\n')
    print("0. Log Out", end = '\n')

    choice = int(input("Enter corresponding number to choose option: "))
    return choice

main()
