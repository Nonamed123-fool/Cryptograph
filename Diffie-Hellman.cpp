//
//  main.cpp
//  Diffie-hellman
//
//  Created by David Sovann on 8/10/2025.
//

#include <iostream>
#include <cstdlib>
#include <ctime>
#include <limits>

using namespace std;

 
/*
 Function to implement Square and Multiply Algorithm for calculate a^b mod n
 a is the base
 b is exponent
 n is modulus
 it return the reslut of a^b mod n
 */
long long squareAndMultiply(long long a, long long b, long long n)
{
    long long result = 1;
    a = a % n;
    
    while (b > 0)
    {
        // If b is odd, multiply a with result
        if (b % 2 == 1)
        {
            result = (result * a) % n;
        }
        
        // b must be even now
        b = b / 2;
        
        // square a and modulo to reduce it down within the range of 0 to n-1
        a = (a * a) % n;
    }
    
    return result;
}

/* Function to check if a number is prime
 n is the number to be check
 True if n is prime, else it false
 */
bool isPrime(int n)
{
    // number less than or equal to 1 not prime
    if (n <= 1) return false;
    
    // 2 and 3 are not prime number
    if (n <= 3) return true;
    
    //if n is divisible by 2 or 3, it not a prime number
    if (n % 2 == 0 || n % 3 == 0) return false;
    
    //check for divisible from 5 square to n
    for (int i = 5; i * i <= n; i += 6)
    {
        if (n % i == 0 || n % (i + 2) == 0)
        {
            return false;
        }
    }
    
    //if it cannot is divisible that it is prime number
    return true;
}

/* Function to find a primitive root modulo p to use in diffie-hellman
 p is the prime modulus
 g is primitive root
 return primitive root modulo p, or -1 if no found
 */
int findPrimitiveRoot(int p)
{
    for (int g = 2; g < p; g++)
    {
        bool isPrimitive = true;
        long long result = 1;
        
        // Check if g is a primitive root
        for (int i = 1; i < p - 1; i++)
        {
            result = (result * g) % p;
            if (result == 1)
            {
                isPrimitive = false;
                break;
            }
        }
        
        //Check if the order of g modulo p is p-1
        if (isPrimitive && (squareAndMultiply(g, p - 1, p) == 1))
        {
            return g;
        }
    }
    
    //if no primitive root is found, return -1
    return -1;
}

/* Function to validate inputs
 p is the modulus
 xA is private key for user A
 xB is private key for user B
 return ture if the input are valid
 */
bool validateInputs(int p, int xA, int xB)
{
    // Check if p is prime and within limit 2 to 100
    if (p <= 1 || p > 100 || !isPrime(p))
    {
        cout << "Error: p must be a prime number between 2 and 100." << endl;
        return false;
    }
    
    // Check if both private keys are within valid range 0 to p-2
    if (xA <= 0 || xA >= p - 1)
    {
        cout << "Error: xA must be between 1 and " << p - 2 << "." << endl;
        return false;
    }
    
    if (xB <= 0 || xB >= p - 1)
    {
        cout << "Error: xB must be between 1 and " << p - 2 << "." << endl;
        return false;
    }
    
    return true;
}

/* Function for manual input
 p is modulus prime number
 xA is private key for user A
 xB is private key for user B
 */
void manualInput(int &p, int &xA, int &xB)
{
    cout << "\n Manual Input " << endl;
    
    do
    {
        cout << "Enter prime number p (2-100): ";
        cin >> p;
    } while (!validateInputs(p, 1, 1)); // Using 1 as temporary values for xA, xB to only check p
    
    do
    {
        cout << "Enter private key for user A (1-" << p - 2 << "): ";
        cin >> xA;
        cout << "Enter private key for user B (1-" << p - 2 << "): ";
        cin >> xB;
    } while (!validateInputs(p, xA, xB));
}

/* Function for auto input
 it genetate a random prime number from 2 to 100 and 2 random private key between 1 to p-2
 p is modulus prime number
 xA is private key for user A
 xB is private key for user B
 */
void autoInput(int &p, int &xA, int &xB)
{
    cout << "\n Auto Input " << endl;
    
    // List of primes up to 100
    int primes[] = {2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97};
    int numPrimes = 25; // total number of prime number
    
    // Randomly select a prime
    p = primes[rand() % numPrimes];
    
    // Generate random private keys
    xA = 1 + rand() % (p - 2);
    xB = 1 + rand() % (p - 2);
    
    cout << "Generated values:" << endl;
    cout << "p = " << p << endl;
    cout << "xA = " << xA << endl;
    cout << "xB = " << xB << endl;
}

/* Function to perform Diffie-Hellman key exchange using the given input and calculate the private key user A and B
 p is modulus prime number
 xA is private key for user A
 xB is private key for user B
 */
void diffieHellman(int p, int xA, int xB)
{
    // Find primitive root g
    int g = findPrimitiveRoot(p);
    
    cout << "\n Diffie-Hellman Key Exchange " << endl;
    cout << "Prime modulus (p): " << p << endl;
    cout << "Primitive root (g): " << g << endl;
    cout << "User A private key (xA): " << xA << endl;
    cout << "User B private key (xB): " << xB << endl;
    
    // Calculate public keys
    long long yA = squareAndMultiply(g, xA, p);
    long long yB = squareAndMultiply(g, xB, p);
    
    cout << "User A public key (yA): " << yA << endl;
    cout << "User B public key (yB): " << yB << endl;
    
    // Calculate shared secret key
    long long keyA = squareAndMultiply(yB, xA, p);
    long long keyB = squareAndMultiply(yA, xB, p);
    
    cout << "\nShared secret key calculated by User A: " << keyA << endl;
    cout << "Shared secret key calculated by User B: " << keyB << endl;
    
    //if keyA and keyB is the same, show the share secret key, else show error
    if (keyA == keyB)
    {
        cout << " Keys match Shared secret key: " << keyA << endl;
    }
    else
    {
        cout << " Error: Keys do not match" << endl;
    }
}

// Function to display menu
void displayMenu()
{
    cout << "\n Diffie-Hellman Key Exchange Program " << endl;
    cout << "1. Manual Input" << endl;
    cout << "2. Auto Input" << endl;
    cout << "3. Exit" << endl;
    cout << "Enter choice (1-3): ";
}


int main()
{
    srand(time(0)); // random number generate
    
    int choice;
    int p, xA, xB;
    
    do
    {
        displayMenu();
        cin >> choice;
        
        switch (choice)
        {
            case 1:
                manualInput(p, xA, xB);
                diffieHellman(p, xA, xB);
                break;
                
            case 2:
                autoInput(p, xA, xB);
                diffieHellman(p, xA, xB);
                break;
                
            case 3:
                break;
                
            default:
                cout << "Invalid choice Please enter 1-4." << endl;
                // Clear input buffer
                //cin.clear();
                break;
        }
        
    } while (choice != 3);
    
    return 0;
}
