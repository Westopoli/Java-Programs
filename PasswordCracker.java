// Demonstration of password entropy
// Why short passwords are insecure
// Why increasing character set dramatically increases attack time
// Compare:
    // lowercase only
    // lowercase + digits
    // full ASCII
// Simulate rate-limited attacker
// Simulate salt in hashing

// Brute-Force Password Cracker (Recursive Search Tree)
// Generate all possible passwords of:
    // Length k
    // From a given character set
// Add constraints like:
    // Must contain at least one digit
    // Must avoid repeated characters
// This creates a recursive search tree:
    // Base case: full-length candidate
    // Recursive case: append next character

// Recurive Function Parameters
    // Current partial password
    // Current depth (password length so far)
    // Attempt counter (tracking how may times the program has to try for a password
      // posteriori comparison of passwords
    // Digit Used boolean (allows pruning) 
        // When a new digit is added to the password (not something that's already in the password)
            // "ab"
            // "a7"
            // if appending '7', digit used is true
            // if appending 'a', digit used is false
        // We'll come up with a rule, like no more than 2 repeated characters in a password
            // Prune branch when more than 2 repeated characters show up
    // Upper Case Used
    // Special Character Used
        // IF
        // < characters digits
        // < 1 uppercase used
        // < 1 special character used
        // < 1 digit used
            // PRUNE
    // Target hash (what success looks like)
        // we'll pass a hash into the program, if the program finds a candidate password that 
        // matches the hash, we've found a potential password. 
        // if we wanted to get fancy we could try and find multiple passwords that match the hash

// Intelligent pruning
    // if remaining characters is less than 3 but still need: 
        // 1 digit
        // 1 uppercase
        // 1 special character
        // PRUNE - impossible to meet policy requirements
    // unmetRequirements > remainingPositions
    
// Could implement multiple policies and call them when running program
    // Weak password cracker (2 characters min, no constraints)
    // Moderate password cracker (3 characters min, 1 digit)
    // Strong password cracker (4 characters min, 1 digit, 1 uppercase, 1 special characters)

// Base case
    // Check if password matches

// Recurisve case
    // append character to current partial password
    // recursively call function with updated password and depth + 1

// Search tree properties
    // IF Character set size = n OR Password length = k
    // THEN
        // Total leaf nodes = n^k
        // Total nodes ≈ (n^(k+1) − 1) / (n − 1)
        // Time complexity = O(n^k)

// 1 - Input
// Read target password or hash
// Parse constraints

// 2 - Recursive Generator
// Build search tree
// Handle base case
// Track metrics:
// Attempt count
// Recursive call count
// Maximum depth reached

// 3 - Validation Engine 
// Hash comparison (SHA256)
// Constraint verification

// 4 - Result
// Total recursive calls
// Total attempts
// Time taken
// Whether match found

import java.util.Scanner;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.nio.charset.StandardCharsets;

public class PasswordCracker {

    static class Password {
        String value; 
        int length;

        Password(String value) {
            this.value = value;
            this.length = value.length();
        }
    }

    static class HashUtil {
        static String SHA256(String input) {
            try {
                MessageDigest digest = MessageDigest.getInstance("SHA-256");
                byte[] hashBytes = digest.digest(input.getBytes(StandardCharsets.UTF_8));

                StringBuilder hexString = new StringBuilder();
                for (byte b : hashBytes) {
                    String hex = Integer.toHexString(0xff & b);
                    if (hex.length() == 1) hexString.append('0');
                    hexString.append(hex);
                }
                return hexString.toString();

            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException(e);
            }
        }
    }

    static class Statistics {
        long recursiveCalls;
        long foundAttempts;
        long startTime;
        long endTime;
        boolean found;

        Statistics() {
            recursiveCalls = 0;
            foundAttempts = 0;
            found = false;
        }
    }

    // Meat of the program, cracks the password by generating candidates and comparing their hashes to the target hash
    static boolean crack(
            String current,
            int depth,
            int maxLength,
            boolean digitUsed,
            boolean upperUsed,
            boolean specialUsed,
            String targetHash,
            Statistics stats) 
        {
            stats.recursiveCalls++;
            // Base case: if current password length matches max length, check hash
            if (depth == maxLength) {
                stats.foundAttempts++;
                String currentHash = HashUtil.SHA256(current);
                if (currentHash.equals(targetHash)) {
                    stats.found = true;
                    return true;
                }
            }

            // array of all characters (lowercase, uppercase, digits, and special characters) to append
            char[] lowerCharSet = "abcdefghijklmnopqrstuvwxyz".toCharArray();
            char[] upperCharSet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ".toCharArray();
            char[] digitCharSet = "0123456789".toCharArray();
            char[] specialCharSet = "!@#$%^&*()".toCharArray();


            if(maxLength == 2) {
                // Weak password: 2 characters long, no constraints
                // Concat Lowercase
                for (char c : lowerCharSet) {
                    if (crack(current + c, depth + 1, maxLength, digitUsed, upperUsed, specialUsed, targetHash, stats)) {
                        return true;
                    }
                }
            }
            else if(maxLength == 3) {
                // Long password: 3 characters long, at least 1 digit
                // Concat Lowercase
                for (char c : lowerCharSet) {
                    if (crack(current + c, depth + 1, maxLength, digitUsed, upperUsed, specialUsed, targetHash, stats)) {
                        return true;
                    }
                }
                // Concat Digits
                for (char c : digitCharSet) {
                    if(!digitUsed) {
                        if (crack(current + c, depth + 1, maxLength, true, upperUsed, specialUsed, targetHash, stats)) {
                        return true;
                        }
                    }
                }
            }
            else if(maxLength == 4) {
                // Strong password: 4 characters long, at least 1 digit, 1 uppercase, and 1 special character
                // Concat Lowercase
                for (char c : lowerCharSet) {
                    if (crack(current + c, depth + 1, maxLength, digitUsed, upperUsed, specialUsed, targetHash, stats)) {
                        return true;
                    }
                }
                // Concat Uppercase
                for (char c : upperCharSet) {
                    if(!upperUsed) {
                        if (crack(current + c, depth + 1, maxLength, digitUsed, true, specialUsed, targetHash, stats)) {
                        return true;
                        }
                    }
                }
                // Concat Digits
                for (char c : digitCharSet) {
                    if(!digitUsed) {
                        if (crack(current + c, depth + 1, maxLength, true, upperUsed, specialUsed, targetHash, stats)) {
                        return true;
                        }
                    }
                }
                // Concat Special Characters
                for (char c : specialCharSet) {
                    if(!specialUsed) {
                        if (crack(current + c, depth + 1, maxLength, digitUsed, upperUsed, true, targetHash, stats)) {
                        return true;
                        }
                    }
                }
            }
            
            return false;
    }

    static int countDigits(Password targetPassword) {
        int digitCount = 0;

        for (char c : targetPassword.value.toCharArray()) {
            if (Character.isDigit(c)) 
                digitCount++;
        }
        return digitCount;
    }

    static int countUpperCase(Password targetPassword) {
        int upperCount = 0;

        for (char c : targetPassword.value.toCharArray()) {
            if (Character.isUpperCase(c)) 
                upperCount++;
        }
        return upperCount;
    }

    static int countSpecialChars(Password targetPassword) {
        int specialCount = 0;

        for (char c : targetPassword.value.toCharArray()) {
            if ("!@#$%^&*()".indexOf(c) >= 0) 
                specialCount++;
        }
        return specialCount;
    }

    static void validateWeak(Password targetPassword, String targetHash, Scanner scanner) {
        while(true) { 
            int digitCount = countDigits(targetPassword);
            int upperCount = countUpperCase(targetPassword);
            int specialCount = countSpecialChars(targetPassword);

            if(targetPassword.length != 2 || digitCount > 0 || upperCount > 0 || specialCount > 0) {
                System.out.println("Password does not meet weak password requirements (exactly 2 lowercase characters).");
                System.out.println("Please input the target password:");
                targetPassword = new Password(scanner.nextLine());
                continue;
            }
            targetHash = HashUtil.SHA256(targetPassword.value);
            System.out.println("EASY MODE ACTIVATED");
            break;
        }
    }

    static void validateModerate(Password targetPassword, String targetHash, Scanner scanner) {
        while(true) {
            int digitCount = countDigits(targetPassword);
            int upperCount = countUpperCase(targetPassword);
            int specialCount = countSpecialChars(targetPassword);
            
            if(targetPassword.length < 3 || digitCount != 1 || upperCount > 0 || specialCount > 0) {
                System.out.println("Password does not meet moderate password requirements (3 characters and exactly 1 digit).");
                System.out.println("Please input the target password:");
                targetPassword = new Password(scanner.nextLine());
                continue;
            }
            targetHash = HashUtil.SHA256(targetPassword.value);
            System.out.println("MEDIUM MODE ACTIVATED");
            break;
        } 
    }

    static void validateStrong(Password targetPassword, String targetHash, Scanner scanner) {
        while(true) {
            int digitCount = countDigits(targetPassword);
            int upperCount = countUpperCase(targetPassword);
            int specialCount = countSpecialChars(targetPassword);
            
            if(targetPassword.length < 4 || digitCount != 1 || upperCount != 1 || specialCount != 1) {
                System.out.println("Password does not meet strong password requirements (4 characters, at least 1 digit, 1 uppercase letter, and 1 special character).");
                System.out.println("Please input the target password:");
                targetPassword = new Password(scanner.nextLine());
                continue;
            }
            targetHash = HashUtil.SHA256(targetPassword.value);
            System.out.println("HARD MODE ACTIVATED");
            break;
        }
    }

    
    
    public static void main(String[] var0) {

        String targetHash = "";
        Statistics stats = new Statistics();
        int option;

        // 1 - Parsing Input
        Scanner scanner = new Scanner(System.in);
        System.out.println("Would you like to input a password or a hash?");
        System.out.println("Input:");
        System.out.println("[1] Password");
        System.out.println("[2] Hash");
        String input = scanner.nextLine();

        try {
            option = Integer.parseInt(input);
        } catch (NumberFormatException e) {
            System.out.println("Invalid input. Please enter an integer:");
            System.out.println("[1] Password");
            System.out.println("[2] Hash");
            return;
        }
        if (option != 1 && option != 2) {
            System.out.println("Invalid input. Please enter an integer:");
            System.out.println("[1] Password");
            System.out.println("[2] Hash");
            return;
        }

        System.out.println("Considering this is a demonstration, password policies are very specific (so your program doesn't end up running for 7 years lol)");
        System.out.println("How strong is the password you want to crack?");
        System.out.println("Input:");
        System.out.println("[2] 2 lowercase characters long (Weak)");
        System.out.println("[3] 3 lowercase characters long (Moderate) only 1 digit");
        System.out.println("[4] 4 characters long (Strong) only 1 digit, only 1 uppercase, & only 1 special character (Hard)");
        int strength;

        while (true) {
            String strengthInput = scanner.nextLine();
            try {
                strength = Integer.parseInt(strengthInput);
            } catch (NumberFormatException e) {
                System.out.println("Invalid input. Please enter one of the valid menue options.");
                continue;
            }

            if (strength == 2 || strength == 3 || strength == 4) {
                break;
            } else {
                System.out.println("Invalid input. Please enter one of the valid menue options.");
            }
        }

        Password targetPassword;
        
        // loop until they input a valid option
        // NEED TO VALIDATE USER ONLY INPUTS 1 OF EACH (LOWERCASE, UPPERCASE, DIGIT, AND SPECIAL CHAR) - does not do that atm, could break program. 
        if(option == 1) {
            System.out.println("Please input the target password:");
            targetPassword = new Password(scanner.nextLine());

            if (strength == 2) { validateWeak(targetPassword, targetHash, scanner); }
            else if (strength == 3) { validateModerate(targetPassword, targetHash, scanner); }
            else if (strength == 4) { validateStrong(targetPassword, targetHash, scanner); }

        }
        if(option == 2) {
            System.out.println("Please input the target hash (I'm trusting you about the char limits 00:");
            System.out.println("Ain't my fault if the password output isn't correct because of your input :)");
            targetHash = scanner.nextLine();
            while(true) {
                if (targetHash.length() != 64) {
                    System.out.println("Invalid hash length. Please input a valid SHA-256 hash (64 characters).");
                    System.out.println("Please input the target hash:");
                    targetHash = scanner.nextLine();
                    continue;
                }
                break;
            }
        }
        // Input fully parsed at this point, targetHash is set and strengthOption is set

        // 2 - Recursive Generator
        // Build search tree
        // Handle base case
        // Track metrics:
        // Attempt count
        // Recursive call count
        // Maximum depth reached

        // use maxLength as difficulty level, since they are the same for all 3 policies
        int maxLength = strength;
        stats.startTime = System.currentTimeMillis();
        /// crack("", 0, maxLength, false, false, false, targetHash, stats);
        stats.endTime = System.currentTimeMillis();

   }
}

// Report Details
// Time Complexity
    // Worst case: O(n^k)
    // Best case: O(1) (if password found immediately)
    // With pruning: reduced branching factor
// Space Complexity
    // Recursion stack depth = O(k)
    // Memory per stack frame small
    // So total auxiliary space = O(k)
// Important:
    // Even though total combinations are exponential,
    // stack usage remains linear in depth.