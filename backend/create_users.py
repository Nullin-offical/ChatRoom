#!/usr/bin/env python3
"""
Script to create multiple realistic users for testing
Generates users with realistic usernames and emails
"""

import random
import string
from auth import register_user
from database import DatabaseContext

# Realistic first names and last names
FIRST_NAMES = [
    "Ahmad", "Ali", "Mohammad", "Hassan", "Hossein", "Reza", "Amir", "Saeed", "Mehdi", "Mostafa",
    "Fatemeh", "Zahra", "Maryam", "Aisha", "Narges", "Parisa", "Sara", "Mina", "Shadi", "Nazanin",
    "John", "Michael", "David", "James", "Robert", "William", "Richard", "Joseph", "Thomas", "Christopher",
    "Emma", "Olivia", "Ava", "Isabella", "Sophia", "Charlotte", "Mia", "Amelia", "Harper", "Evelyn"
]

LAST_NAMES = [
    "Ahmadi", "Mohammadi", "Hassani", "Hosseini", "Rezaei", "Amiri", "Saeedi", "Mehdizadeh", "Mostafavi", "Karimi",
    "Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis", "Rodriguez", "Martinez",
    "Anderson", "Taylor", "Thomas", "Hernandez", "Moore", "Martin", "Jackson", "Thompson", "White", "Lopez"
]

# Email domains
EMAIL_DOMAINS = [
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "icloud.com",
    "protonmail.com", "mail.com", "aol.com", "live.com", "msn.com"
]

def generate_realistic_username(first_name, last_name):
    """Generate a realistic username from first and last name"""
    patterns = [
        f"{first_name.lower()}{last_name.lower()}",
        f"{first_name.lower()}_{last_name.lower()}",
        f"{first_name.lower()}{random.randint(10, 99)}",
        f"{first_name.lower()}{last_name.lower()[:3]}",
        f"{first_name.lower()}_{random.randint(100, 999)}",
        f"{last_name.lower()}{first_name.lower()}",
        f"{first_name.lower()}{random.choice(string.ascii_lowercase)}{random.randint(10, 99)}"
    ]
    return random.choice(patterns)

def generate_realistic_email(first_name, last_name):
    """Generate a realistic email from first and last name"""
    patterns = [
        f"{first_name.lower()}.{last_name.lower()}@{random.choice(EMAIL_DOMAINS)}",
        f"{first_name.lower()}{last_name.lower()}@{random.choice(EMAIL_DOMAINS)}",
        f"{first_name.lower()}_{last_name.lower()}@{random.choice(EMAIL_DOMAINS)}",
        f"{first_name.lower()}{random.randint(10, 99)}@{random.choice(EMAIL_DOMAINS)}",
        f"{last_name.lower()}.{first_name.lower()}@{random.choice(EMAIL_DOMAINS)}"
    ]
    return random.choice(patterns)

def generate_password():
    """Generate a realistic password"""
    # Mix of letters, numbers, and symbols
    letters = string.ascii_letters
    digits = string.digits
    symbols = "!@#$%^&*"
    
    password = (
        ''.join(random.choice(letters) for _ in range(6)) +
        ''.join(random.choice(digits) for _ in range(2)) +
        ''.join(random.choice(symbols) for _ in range(1))
    )
    
    # Shuffle the password
    password_list = list(password)
    random.shuffle(password_list)
    return ''.join(password_list)

def create_users(count=10):
    """Create specified number of realistic users"""
    print(f"Creating {count} realistic users...")
    print("=" * 50)
    
    successful_users = []
    failed_users = []
    
    for i in range(count):
        # Generate random names
        first_name = random.choice(FIRST_NAMES)
        last_name = random.choice(LAST_NAMES)
        
        # Generate username and email
        username = generate_realistic_username(first_name, last_name)
        email = generate_realistic_email(first_name, last_name)
        password = generate_password()
        
        print(f"Creating user {i+1}/{count}:")
        print(f"  Name: {first_name} {last_name}")
        print(f"  Username: {username}")
        print(f"  Email: {email}")
        print(f"  Password: {password}")
        
        # Register the user
        user, error = register_user(username, email, password)
        
        if user:
            successful_users.append({
                'name': f"{first_name} {last_name}",
                'username': username,
                'email': email,
                'password': password
            })
            print(f"  ✅ Success!")
        else:
            failed_users.append({
                'name': f"{first_name} {last_name}",
                'username': username,
                'email': email,
                'password': password,
                'error': error
            })
            print(f"  ❌ Failed: {error}")
        
        print("-" * 30)
    
    # Summary
    print("\n" + "=" * 50)
    print("SUMMARY:")
    print(f"✅ Successful: {len(successful_users)}")
    print(f"❌ Failed: {len(failed_users)}")
    
    if successful_users:
        print("\n✅ SUCCESSFUL USERS:")
        for i, user in enumerate(successful_users, 1):
            print(f"{i}. {user['name']} - {user['username']} - {user['email']} - {user['password']}")
    
    if failed_users:
        print("\n❌ FAILED USERS:")
        for i, user in enumerate(failed_users, 1):
            print(f"{i}. {user['name']} - {user['username']} - {user['email']} - Error: {user['error']}")
    
    return successful_users, failed_users

def main():
    """Main function"""
    print("Realistic User Generator for ChatRoom")
    print("=" * 50)
    
    try:
        count = int(input("How many users do you want to create? (default: 10): ") or "10")
        if count <= 0:
            print("Please enter a positive number.")
            return
        
        successful, failed = create_users(count)
        
        print(f"\n🎉 User creation completed!")
        print(f"Total users created: {len(successful)}")
        
    except KeyboardInterrupt:
        print("\n\nOperation cancelled by user.")
    except ValueError:
        print("Please enter a valid number.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main() 