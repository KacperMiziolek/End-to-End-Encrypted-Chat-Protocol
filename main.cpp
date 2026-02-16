/**
 * Project: End-to-End Encrypted Chat Protocol 
 * Author:  Kacper Miziolek
 * GitHub:  github.com/KacperMiziolek
 *
 * Description:
 * This program demonstrates a secure communication protocol using Elliptic Curve Cryptography (ECC).
 * 
 * Key features:
 * - NIST P-256 curve parameters,
 * - ECDH (Elliptic Curve Diffie-Hellman),
 * - ECDSA (Elliptic Curve Digital Signature Algorithm),
 * - SHA-256 for hashing and key derivation,
 * - XOR Cipher for symmetric encryption.
 *
 * Dependencies:
 * - BigInt Arithmetic: Uses "InfInt.h" header only library from https://github.com/sercantutar/infint,
 * - Hashing: Uses "picosha2.h" from https://github.com/okdshin/PicoSHA2.
 *
 * Note:
 * This code is for EDUCATIONAL PURPOSES ONLY.
 * Code is not optimized for performance or security.
 * Do not use to protect real sensitive data.
 */

#include "bigint.h"
#include "picosha2.h"
#include <iostream>
#include <sstream>
#include <random>

using bigint = InfInt; //previously used library was too slow, so I switched to InfInt, for simplicity I kept the old name

//NIST recomendations for P-256 curve
bigint p("115792089210356248762697446949407573530086143415290314195533631308867097853951");
bigint n("115792089210356248762697446949407573529996955224135760342422259061068512044369");
bigint a("115792089210356248762697446949407573530086143415290314195533631308867097853948");
bigint b("41058363725152142129326129780047268409114441015993725554835256314039467401291");
bigint Gx("48439561293906451759052585252797914202762949526041747995844080717082404635286");
bigint Gy("36134250956749795798585127919587881956611106672985015071877198253568414405109");
bigint c("57436011470200155964173534038266061871440426244159038175955947309464595790349");


struct Point{
        
        bigint x; //x coordinate of the point on curve
        bigint y; //y coordinate of the point on curve
        bool isInfinity;

        Point(){ //constructor for point at infinity
            isInfinity=true;
        }
        Point(bigint new_x, bigint new_y){ //constructor for point with coordinates
            x=new_x;
            y=new_y;
            isInfinity=false;
        }

};


bigint positive_modulo(bigint n,bigint p) {
    
    if(n%p>= bigint(0))
    return n%p;
    
    return n%p+p;
}


bigint modulo_power(bigint base, bigint exponent, bigint M){ //fast modular exponentiation
    
    bigint res=1;
    base = positive_modulo(base, M);
   
//if the bit is 1 we multiply the result by the current base, then we square the base and move to the next bit
//if the bit is 0 we just square the base and move to the next bit    
    while(exponent>0){ 
        
        if(exponent%2==1){
            
            res=(res*base)%M;
            
        }
        
        base=(base*base)%M;
        
        exponent=exponent / 2;
        
    }
    return res;
}


bigint modInverse(bigint A, bigint M) { //I choose fermat's little theorem for modular inverse, because p is prime, and it is faster than eec

    bigint res;

    res=modulo_power(A,M-2,M);

    return res;

    
    
}


Point addPoints(Point P, Point Q) {
    if (P.isInfinity) return Q;
    if (Q.isInfinity) return P;

    
    if (P.x == Q.x && P.y != Q.y) return Point();

    if (P.x == Q.x && P.y == Q.y) {
        
        bigint s = positive_modulo((bigint(3) * P.x * P.x + a) * modInverse(bigint(2) * P.y, p), p);
        
        bigint x3 = positive_modulo(s * s - P.x - Q.x, p);
        bigint y3 = positive_modulo(s * (P.x - x3) - P.y, p);
        return Point(x3, y3);
    } else {
        
        bigint s = positive_modulo((P.y - Q.y) * modInverse(P.x - Q.x, p), p);
        
        bigint x3 = positive_modulo(s * s - P.x - Q.x, p);
        bigint y3 = positive_modulo(s * (P.x - x3) - P.y, p);
        return Point(x3, y3);
    }
}


Point ScalarMultiplication(Point P, bigint n){

    Point R;
    Point temp = P;

    while(n>0){

        if(n%2==1) R=addPoints(R, temp); //for odd 

        temp=addPoints(temp,temp); //for even and odd

        n=n/2; //go to the next bit

    }
    return R;




}


std::string bigintIntoString(bigint a){

    std::stringstream ss;
    ss << a;
    return ss.str();
}


std::string XORcipher(std::string data, std::string key) {
    std::string result = data;
    
    if (key.empty()) return data;

    for (size_t i = 0; i < data.size(); i++) {
       
        char keyChar = key[i % key.size()];
        
        
        result[i] = data[i] ^ keyChar;
    }
    
    return result;
}


bigint genPrivKey(){

    bigint key=0;

    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<> distr(0,255);
    for(int i=0; i<32;i++){
      
      bigint randomByte=distr(gen);
      key=key*256; //creating space for next byte
      key=key+randomByte; //adding next byte
      
    }
    if(key >= n || key == 0){
        return genPrivKey();
    }
    return key;
}

bigint genTempVal(){

    bigint key=0;

    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<> distr(0,255);
    for(int i=0; i<32;i++){
      
      bigint randomByte=distr(gen);
      key=key*256; //creating space for next byte
      key=key+randomByte; //adding next byte
      
    }
    if(key >= n || key == 0){
        return genTempVal();
    }
    return key;
}


bigint hexStringtoBigInt(std::string hexHash){ //my hash function returns hexString, signature() needs integers

    bigint hexBigint=0;

    for( char c: hexHash){
    
        hexBigint=hexBigint*16;
    
        int digitValue=0;

        if(c>= '0' && c<='9')
            digitValue=c-'0';

        else if(c>='a' && c<='f')
            digitValue=c-'a'+10;

    hexBigint=hexBigint+digitValue;
}
    return hexBigint;
}
std::string hashFunction(std::string message){
    
    std::string src_str = message;
    std::string hash_hex_str = picosha2::hash256_hex_string(src_str);
    return hash_hex_str;

    
}

Point signature(std::string message, bigint PrivKey){ //generating signature
    
    bigint e = hexStringtoBigInt(hashFunction(message));
    bigint k = genTempVal();
    Point G = Point(Gx,Gy);
    Point R = ScalarMultiplication(G, k);
    bigint r = positive_modulo(R.x, n);
    if(r==0) return signature(message, PrivKey);

    bigint s = positive_modulo(modInverse(k,n) * (e+(r*PrivKey)),n);

    
    Point Signatutre = Point(r,s);

    return Signatutre;
}

bool verify_signature(Point Signature, std::string message,Point PubKey ){ //verifying signature

    Point G = Point(Gx,Gy);

    if(Signature.x>n-1 || Signature.x<1) return false;
    if(Signature.y>n-1 || Signature.y<1) return false;

    bigint e = hexStringtoBigInt(hashFunction(message));
    bigint w = modInverse(Signature.y, n);
    bigint u1 = positive_modulo(e*w, n);
    bigint u2 = positive_modulo(Signature.x*w, n);

    Point P = addPoints(ScalarMultiplication(G, u1), ScalarMultiplication(PubKey, u2));
    
    if(positive_modulo(P.x,n) == Signature.x) return true;
    else return false;
    



}
   
int main() {

    /*Example 1:
    1. Both sides keys are generated
    2. Shared secret is verified
    3. A writes a message
    4. Signature is created using A's hashed message and A's private key
    5. Message is encypted using hashed shared secret as a key in XORcipher (possible future update: switch to more complex symmetric encryption)
    6. A sends encrypted message and signature
    7. B decrypts A's message using shared secret
    8. B creates a hash of A's decrpyted message
    9. B verifies if signature is valid using A's hashed message and A's public key
    10.
    */
    Point G(Gx, Gy); //init generator point
    std::string message; 
    std::cout<<std::endl;  
    std::cout<<"////////////////////////// \n";
    std::cout<<"///STARTING PROTOCOL.../// \n";
    std::cout<<"////////////////////////// \n";
    std::cout<<std::endl;  
    
    std::cout<<"Generating keys for A... \n";//key generation for A
    std::cout<<std::endl;
    std::cout<<"Generating A's private key..."<<'\n';
    std::cout<<std::endl;
    bigint PrivKeyAlice=genPrivKey();
    std::cout<<"A's private key is: \n"<<PrivKeyAlice<<'\n';
    std::cout<<std::endl;
    std::cout<<"Generating A's public key..."<<'\n';
    Point PubKeyAlice=ScalarMultiplication(G, PrivKeyAlice);
    std::cout<<std::endl;
    std::cout<<"A's public key is: \n"<<PubKeyAlice.x<<'\n'; //y can be calculated from x, by skipping it we limit overhead
    std::cout<<std::endl;
    std::cout<<"****************************** \n";
    std::cout<<std::endl;

    std::cout<<"Generating keys for B... \n";//key generation for B
    std::cout<<std::endl;
    std::cout<<"Generating B's private key..."<<'\n';
    bigint PrivKeyBob=genPrivKey();
    std::cout<<std::endl;
    std::cout<<"B's private key is: \n"<<PrivKeyBob<<'\n';
    std::cout<<std::endl;
    std::cout<<"Generating B's public key..."<<'\n';
    std::cout<<std::endl;
    Point PubKeyBob=ScalarMultiplication(G, PrivKeyBob);
    std::cout<<"B's public key is: \n"<<PubKeyBob.x<<'\n';//y can be calculated from x, by skipping it we limit overhead
    std::cout<<std::endl;
    std::cout<<"****************************** \n";
    std::cout<<std::endl;
    
    std::cout<<"Checking for safe connection... \n";//shared secret generation and verification
    std::cout<<std::endl;
    Point SecretA = ScalarMultiplication(PubKeyBob, PrivKeyAlice);
    Point SecretB = ScalarMultiplication(PubKeyAlice, PrivKeyBob);
    if(SecretA.x==SecretB.x && SecretA.y==SecretB.y)
        std::cout<<"established safe connection between A and B \n";
        else{
            std::cout<<"couldn't establish safe connection between A and B \n";
            return -1;
        } 
    
    std::cout<<std::endl;
    std::cout<<"****************************** \n";
    std::cout<<std::endl;
    
    std::cout<<"Message, Signature and Encryption\n";
    std::cout<<std::endl;
    std::cout<<"Input message: \n";
    std::getline(std::cin >> std::ws, message); 
    if(message=="") return -1;
    std::cout<<std::endl;
    std::cout<<"****************************** \n";
    std::cout<<std::endl;

    std::cout<<"Creating signature for A's message... \n";//signature generation
    std::cout<<std::endl;
    Point SignatureA=signature(message, PrivKeyAlice);
    std::cout<<"Signature for A's message: \n"<<SignatureA.x<<'\n'<<SignatureA.y<<'\n';
    std::cout<<std::endl;
    std::cout<<"****************************** \n";
    std::cout<<std::endl;

    std::cout<<"Enctrpyting A's message and signature... \n";//encryption using shared secret
    std::cout<<std::endl;
    std::string KeyA=hashFunction(bigintIntoString(SecretA.x));
    std::string encryptedMessage=XORcipher(message, KeyA);
    std::cout<<"Enctrpyted message: \n"<<encryptedMessage<<'\n';
    std::cout<<std::endl;
    std::cout<<"****************************** \n";
    std::cout<<std::endl;
    
    std::cout<<"Decrpyting A's message... \n";
    std::cout<<std::endl;
    std::string KeyB=hashFunction(bigintIntoString(SecretB.x));//Diffie-Hellman key exchange ensures that Secrets are the same
    std::string decryptedMessage=XORcipher(encryptedMessage, KeyB);
    std::cout<<std::endl;
    std::cout<<"Validating A's signature...\n";
    std::cout<<std::endl;
    if(verify_signature(SignatureA, decryptedMessage, PubKeyAlice)==true){

        std::cout<<"A's signature has been verified, no tampering detected\n";
        std::cout<<std::endl;
        std::cout<<"Decrytped message: \n"<<decryptedMessage<<'\n';
        std::cout<<std::endl;
    
    }
    else{
        std::cout<<"A's signature has not been verified \n";
    }

    return 0;
}

