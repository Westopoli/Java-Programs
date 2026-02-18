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

    // indidivdual password class to store password value and length for easy access
    static class Password {
        String value; 
        int length;

        Password(String value) {
            this.value = value;
            this.length = value.length();
        }
    }

    // Policy class to store password policy requirements and compute total combinations for progress tracking
    // Additional policies can be easily added
    static class Policy {
        int length;

        boolean requireDigit;
        boolean requireUpper;
        boolean requireSpecial;

        boolean allowDigit;
        boolean allowUpper;
        boolean allowSpecial;
        boolean allowLower = true;

        long totalCombinations;   

        // Character set sizes (constants)
        static final int LOWER_COUNT = 26;
        static final int UPPER_COUNT = 26;
        static final int DIGIT_COUNT = 10;
        static final int SPECIAL_COUNT = 10;

        Policy(int length,
            boolean requireDigit,
            boolean requireUpper,
            boolean requireSpecial,
            boolean allowDigit,
            boolean allowUpper,
            boolean allowSpecial) {

            this.length = length;
            this.requireDigit = requireDigit;
            this.requireUpper = requireUpper;
            this.requireSpecial = requireSpecial;

            this.allowDigit = allowDigit;
            this.allowUpper = allowUpper;
            this.allowSpecial = allowSpecial;

            this.totalCombinations = computeTotalCombinations();
        }

        // Computes total combinations based on policy requirements for progress bar 
        private long computeTotalCombinations() {
            int allowedPerPosition = 0;

            if (allowLower) allowedPerPosition += LOWER_COUNT;
            if (allowUpper) allowedPerPosition += UPPER_COUNT;
            if (allowDigit) allowedPerPosition += DIGIT_COUNT;
            if (allowSpecial) allowedPerPosition += SPECIAL_COUNT;

            // Case 1: No exact requirements
            if (!requireDigit && !requireUpper && !requireSpecial) {
                return (long) Math.pow(allowedPerPosition, length);
            }

            // Case 2: Exactly 1 digit only (moderate)
            if (requireDigit && !requireUpper && !requireSpecial) {

                long positionChoices = length;
                long digitChoices = DIGIT_COUNT;
                long remainingChoices =
                        (long) Math.pow(LOWER_COUNT, length - 1);

                return positionChoices * digitChoices * remainingChoices;
            }

            // Case 3: Exactly 1 digit, 1 upper, 1 special (strong)
            if (requireDigit && requireUpper && requireSpecial) {

                long positionPermutations =
                        length * (length - 1) * (length - 2);

                long remainingChoices =
                        (long) Math.pow(LOWER_COUNT, length - 3);

                return positionPermutations
                        * DIGIT_COUNT
                        * UPPER_COUNT
                        * SPECIAL_COUNT
                        * remainingChoices;
            }

            // Default: treat as unrestricted allowed-set case (5 character policy)
            double result = Math.pow(allowedPerPosition, length);
            if (result > Long.MAX_VALUE) {
                return Long.MAX_VALUE;
            }
            return (long) result;

        }


    }

    // Utility class for hashing passwords using SHA-256
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

    // Statistics class to track recursive calls, attempts, time taken, and whether password was found
    static class Statistics {
        long recursiveCalls;
        long attempts;
        long startTime;
        long endTime;
        boolean found;

        Statistics() {
            recursiveCalls = 0;
            attempts = 0;
            found = false;
        }
    }

    // Meat of the program, cracks the password by generating candidates and comparing their hashes to the target hash
    static boolean crack(
            String current,
            int depth,
            boolean digitUsed,
            boolean upperUsed,
            boolean specialUsed,
            String targetHash,
            Statistics stats,
            Policy policy) 
        {
            stats.recursiveCalls++;

            // Pruning section: 
                // Based on the policy, sometimes we can prune passwords that we know won't work without fully generating them
                // For example, if we only need 1 digit, computing another password with a second digit is a waste of time -> prune

            // Base case: if current password length matches max length, check hash
            if (depth == policy.length) {
                stats.attempts++;
                // edge case 
                long updateInterval = Math.max(1, policy.totalCombinations / 5000);
                if (stats.attempts % updateInterval == 0) { 
                    updateProgress(stats.attempts, policy.totalCombinations - stats.attempts); // fix this -> even when not found progress bar only reaches like 25%
                }
                // Prune if password doesn't meet policy requirements
                if (policy.requireDigit && !digitUsed) 
                    return false;
                if (policy.requireUpper && !upperUsed) 
                    return false;
                if (policy.requireSpecial && !specialUsed) 
                    return false;

                // Not pruned yet, passowrd is eligible, check hash
                String currentHash = HashUtil.SHA256(current);
                if (currentHash.equals(targetHash)) {
                    stats.found = true;
                    return true;
                }
                return false;
            }

            // array of all characters (lowercase, uppercase, digits, and special characters) to append
            char[] lowerCharSet = "abcdefghijklmnopqrstuvwxyz".toCharArray();
            char[] upperCharSet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ".toCharArray();
            char[] digitCharSet = "0123456789".toCharArray();
            char[] specialCharSet = "!@#$%^&*()".toCharArray();

            // Lowercase chars are always checked (could technically track whether a password has lowercase or not and save computation time... but ehhhh)
            for (char c : lowerCharSet) {
                if (crack(current + c, depth + 1,
                        digitUsed, upperUsed, specialUsed,
                        targetHash, stats, policy))
                    return true;
            }
            if (policy.allowUpper && !upperUsed) {
                for (char c : upperCharSet) {
                    if (crack(current + c, depth + 1,
                            digitUsed, true, specialUsed,
                            targetHash, stats, policy))
                        return true;
                }
            }
            if (policy.allowDigit && !digitUsed) {
                for (char c : digitCharSet) {
                    if (crack(current + c, depth + 1,
                            true, upperUsed, specialUsed,
                            targetHash, stats, policy))
                        return true;
                }
            }
            if (policy.allowSpecial && !specialUsed) {
                for (char c : specialCharSet) {
                    if (crack(current + c, depth + 1,
                            digitUsed, upperUsed, true,
                            targetHash, stats, policy))
                        return true;
                }
            }            
            return false;
    }

    // Simple utility functions to count digits, uppercase letters, and special characters in a password for validation purposes
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

    // Utility functions to print menu options for user input
    static void printPolicyOptions() {
        System.out.println("[2] 2 lowercase characters long (Weak)");
        System.out.println("[3] 3 lowercase characters long (Moderate) only 1 digit");
        System.out.println("[4] 4 characters long (Strong) only 1 digit, only 1 uppercase, & only 1 special character (Hard)");
        System.out.println("[5] 5 characters long (any number of digits, uppercase, and special characters allowed, but nothing else)");
    }

    static void printMainMenu() {
        System.out.println("[1] Password");
        System.out.println("[2] Hash");
    }

    static void printSubMenu() {
        System.out.println("[1] Hash this password for me");
        System.out.println("[2] I already have the hash (why the heck do you have that, you malicious son of a gun)");
    }

    // Validation functions for each password policy, loops until user inputs a valid password that meets the policy requirements, then returns the validated password
    static Password validateLength(int strength,Password targetPassword, String targetHash, Scanner scanner) {
        if(strength != 5) {
            throw new IllegalArgumentException("Invalid strength option for length validation. Expected 5.");
        }
        while(true) { 
            // if password doesn't meet length requirement or contains a character not in the character set, ask for input again
            if (strength == 5 && targetPassword.length != 5) {
                System.out.println("Password does not meet length requirement (at least 5 characters).");
                System.out.println("Please input the target password:");
                targetPassword = new Password(scanner.nextLine());
                continue;
            }
            
            targetHash = HashUtil.SHA256(targetPassword.value);
            return targetPassword;
        }
    }

    static Password validateWeak(Password targetPassword, String targetHash, Scanner scanner) {
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
            return targetPassword;
        }
    }

    static Password validateModerate(Password targetPassword, String targetHash, Scanner scanner) {
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
            return targetPassword;
        } 
    }

    static Password validateStrong(Password targetPassword, String targetHash, Scanner scanner) {
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
            return targetPassword;
        }
    }

    // Progress bar utility function to display cracking progress based on attempts and total combinations
        // source: chatGPT      --------------> @yasemin should we include this? 
    static void updateProgress(long current, long total) {
        int barWidth = 80;

        double progress = (double) current / total;
        int filled = (int) (barWidth * progress);

        StringBuilder bar = new StringBuilder();
        bar.append("Progress: [");

        for (int i = 0; i < barWidth; i++) {
            if (i < filled) {
                bar.append("#");
            } else {
                bar.append("-");
            }
        }

        bar.append("] ");
        bar.append(String.format("%.2f", progress * 100)).append("%");

        System.out.print("\r" + bar.toString());
    }
    
    public static void main(String[] var0) {
        // Global variables
        String targetHash = "";
        Statistics stats = new Statistics();
        int option;
        int subOption;
        int strength;
        Policy policy = null;
        Password targetPassword;

        // 1 - Parsing Input
        Scanner scanner = new Scanner(System.in);
        System.out.println("Would you like to input a password or a hash?");
        System.out.println("Input:");
        printMainMenu();
        String input = scanner.nextLine();

        // While loops so user cannot move on without inputting valid options
        while(true) {
            try {
                option = Integer.parseInt(input);
            } catch (NumberFormatException e) {
                System.out.println("Invalid input. Please enter an integer:");
                printMainMenu();
                input = scanner.nextLine();
                continue;
            }
            if (option == 1 || option == 2) {
                break;
            }
            else {
                System.out.println("Invalid input. Please enter an integer:");
                printMainMenu();
                input = scanner.nextLine();
                continue;
            }
        }

        System.out.println("Considering this is a demonstration, password policies are very specific (so your program doesn't end up running for 7 years lol).");
        System.out.println("It's also easier to crack a password when you know the policy.");
        System.out.println("How strong is the password you want to crack?");
        System.out.println("Input:");
        printPolicyOptions();

        // Policy selection loop (switch statment would be clearner if you're bored @yasemin)
        while (true) {
            String strengthInput = scanner.nextLine();
            try {
                strength = Integer.parseInt(strengthInput);
            } catch (NumberFormatException e) {
                System.out.println("Invalid input. Please enter one of the valid menue options.");
                printPolicyOptions();
                continue;
            }

            if (strength == 2) {   // Weak
                policy = new Policy(
                    2,
                    false, false, false,  
                    false, false, false   
                );
                break;
            }
            else if (strength == 3) {  // Moderate
                policy = new Policy(
                    3,
                    true, false, false,   
                    true, false, false    
                );
                break;
            }
            else if (strength == 4) {  // Strong
                policy = new Policy(
                    4,
                    true, true, true,     // require all
                    true, true, true      // allow all
                );
                break;
            }
            else if (strength == 5) {  // 5 characters, anything goes
                policy = new Policy(
                    5,
                    false, false, false,
                    true, true, false
                );

                break;
            }
            else {
                System.out.println("Invalid input. Please enter one of the valid menue options.");
                printPolicyOptions();
                continue;
            }
        }
        
        // loop until they input a valid option (uses validate function)
        if(option == 1) {
            System.out.println("Please input the target password:");
            Password unvalidatedPassword = new Password(scanner.nextLine());

            if (strength == 2) { 
                targetPassword = validateWeak(unvalidatedPassword, targetHash, scanner); 
            }
            else if (strength == 3) { 
                targetPassword = validateModerate(unvalidatedPassword, targetHash, scanner); 
            }
            else if (strength == 4) { 
                 targetPassword = validateStrong(unvalidatedPassword, targetHash, scanner);
            }
            else {
                targetPassword = validateLength(strength, unvalidatedPassword, targetHash, scanner);
            }

            targetHash = HashUtil.SHA256(targetPassword.value);
            System.out.println("Hash: " + targetHash);
        }
        if(option == 2) {
            System.out.println("Please input: ");
            printSubMenu();
            input = scanner.nextLine();
            try {
                subOption = Integer.parseInt(input);
            } catch (NumberFormatException e) {
                System.out.println("Invalid input. Please enter an integer:");
                printSubMenu();
                return;
            }
            if (subOption != 1 && subOption != 2) {
                System.out.println("Invalid input. Please enter an integer:");
                printSubMenu();
                return;
            }
            if(subOption == 1) {
                System.out.println("Please input the target password:");
                Password unvalidatedPassword = new Password(scanner.nextLine());

                if (strength == 2) { targetPassword = validateWeak(unvalidatedPassword, targetHash, scanner); }
                else if (strength == 3) { targetPassword = validateModerate(unvalidatedPassword, targetHash, scanner); }
                else if (strength == 4) { targetPassword = validateStrong(unvalidatedPassword, targetHash, scanner); }
                else { targetPassword = validateLength(strength, unvalidatedPassword, targetHash, scanner); }

                targetHash = HashUtil.SHA256(targetPassword.value);
                System.out.println("Hash: " + targetHash);
            }
            else {
                System.out.println("Please input the target hash:");
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
        }
        // Input fully parsed at this point, targetHash is set and strengthOption is set

        // 2 - Cracking with recursion
        stats.startTime = System.currentTimeMillis();
        // show progress bar as soon as program starts cracking
        updateProgress(0, policy.totalCombinations);
        boolean found = crack(
            "",
            0,
            false, false, false,
            targetHash,
            stats,
            policy
        );
        // println to keep progress bar
        System.out.println(); 
        stats.endTime = System.currentTimeMillis();
        if (found) {
            System.out.println("Password hash found!");
            System.out.println("Password as hash: " + targetHash);
        } 
        else {
            System.out.println("Password not found.");
        }
        System.out.println("Total recursive calls: " + stats.recursiveCalls);
        System.out.println("Total comparisons: " + stats.attempts);
        System.out.println("Total branches pruned: " + (stats.recursiveCalls - stats.attempts));
        System.out.println("Time taken: " + (stats.endTime - stats.startTime) + " ms");

   }
}

// Report Details
// For edge cases, you probably can just try and input something wrong or something that is an edge case and show
// the program flagging and handling the exception
// Most of the program code is edge case handling and user input validation lol, I probably went a little overboard
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