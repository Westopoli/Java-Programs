# Java-Programs
Programs designed to convey algorithm analysis literacy in Java.

## Authors
    Westley Yarlott
    Yasemin Tuncer  

# Brute-Force Password Cracker
    Brute-Force Password Cracker to demonstrate password entropy, why increasing character set dramatically increases attack time
    and why short passwords are insecure

## Features
    - 2 input options
    - 4 password policies
    - Pruning based on policy req


## Password Policies
    - Weak --> lowercase
    - Moderate --> lowercase + 1 digit
    - Strong --> 1 digit, 1 uppercase, 1 special character
    - Any combination of uppercase, special character, and digits


## Prerequisites
    - Need Java 17 or higher
    

## How to Run

    java PasswordCracker

    Only if it needs to be recompiled:
    javac PasswordCracker.java
    java PasswordCracker

## Sample Output

Would you like to input a password or a hash?
Input:
[1] Password
[2] Hash
1

Considering this is a demonstration, password policies are very specific (so your program doesn't end up running for 7 years lol).
It's also easier to crack a password when you know the policy.
How strong is the password you want to crack?
Input:
[2] 2 lowercase characters long (Weak)
[3] 3 lowercase characters long (Moderate) only 1 digit
[4] 4 characters long (Strong) only 1 digit, only 1 uppercase, & only 1 special character (Hard)
[5] 5 characters long (any number of digits, uppercase, and special characters allowed, but nothing else)
2

Please input the target password:
ab
Hash: fb8e20fc2e4c3f248c60c39bd652f3c1347298bb977b8b4d5903b85055620603
Progress: [--------------------------------------------------------------------------------] 0.30%
Password hash found!
Password as hash: fb8e20fc2e4c3f248c60c39bd652f3c1347298bb977b8b4d5903b85055620603
Total recursive calls: 4
Total comparisons: 2
Total branches pruned: 2

## Complexity 

    n --> character set size
    k --> password length
    Time Complexity (worse case): O(n^k)
    Time Complexity (best case): O(1)
