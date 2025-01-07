import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

public class RSAKeyCracker {

    public static void main(String[] args) {
        try {
            // Clé publique en base64
            String publicKeyBase64 = """
            MIIBJTANBgkqhkiG9w0BAQEFAAOCARIAMIIBDQKCAQQAjaVpGbUm1FIlrO1L5kUi
            zvBKY5ELn2/+prESVUEBO+RdSLb7JnG3VA5qTgtV46nkxFqNX1SgaZxlMtShKH+s
            sAixxW411gHcKp4uZlGJ6qNdIte+olLB7PJwMatlfVs16CzecPglnS4U6YbzYuPo
            bnvY5IEqUvLozC9puLDJWXeP2yQKjhfLlXJFcBLYO2xycpDlC459oo/r36v1I9oD
            uUuUMir0IfnKAq3mBNqrks2cKCRENvEV/b7XbSyFAHrKf85JiTr4DnlVYy7HuJ9W
            +rAYduD+iCmaNzQNQ5yy4Bs8B+YMiEdCG/4EnVmVQGsm9KCLINFJs8YarqNTHWL4
            +NHihwIDAQAB
            """;

            // Décoder la clé publique
            byte[] publicKeyBytes = Base64.getMimeDecoder().decode(publicKeyBase64);
            X509EncodedKeySpec spec = new X509EncodedKeySpec(publicKeyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            RSAPublicKey publicKey = (RSAPublicKey) keyFactory.generatePublic(spec);

            // Extraire le module n
            BigInteger n = publicKey.getModulus();
            System.out.println("Modulus (n): " + n);

            // Générer les nombres premiers p et q
            BigInteger p = BigInteger.ZERO;
            BigInteger q = BigInteger.ZERO;
            List<BigInteger> primes = generatePrimes(n.sqrt());

            for (BigInteger prime : primes) {
                if (n.mod(prime).equals(BigInteger.ZERO)) {
                    q = prime;
                    p = n.divide(q);
                    if (p.compareTo(q) > 0) {
                        break;
                    }
                }
            }

            if (p.equals(BigInteger.ZERO) || q.equals(BigInteger.ZERO)) {
                System.out.println("Échec de la factorisation.");
                return;
            }

            System.out.println("p: " + p);
            System.out.println("q: " + q);

            // Calcul des paramètres de la clé privée
            BigInteger phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
            BigInteger e = BigInteger.valueOf(65537); // Exposant public
            BigInteger d = e.modInverse(phi);
            BigInteger e1 = d.mod(p.subtract(BigInteger.ONE));
            BigInteger e2 = d.mod(q.subtract(BigInteger.ONE));
            BigInteger coef = q.modInverse(p);

            // Affichage des résultats
            System.out.println("Clé privée (exposant d): " + d);
            System.out.println("e1: " + e1);
            System.out.println("e2: " + e2);
            System.out.println("Coefficient (q^-1 mod p): " + coef);

        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

    // Générateur de nombres premiers jusqu'à une limite
    private static List<BigInteger> generatePrimes(BigInteger limit) {
        List<BigInteger> primes = new ArrayList<>();
        BigInteger candidate = BigInteger.valueOf(2);

        while (candidate.compareTo(limit) <= 0) {
            if (isPrime(candidate)) {
                primes.add(candidate);
            }
            candidate = candidate.add(BigInteger.ONE);
        }

        return primes;
    }

    // Test de primalité basique
    private static boolean isPrime(BigInteger number) {
        return number.isProbablePrime(10); // Vérification probabiliste
    }
}
