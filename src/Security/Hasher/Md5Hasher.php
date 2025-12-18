<?php

// src/Security/Hasher/Md5Hasher.php
namespace App\Security\Hasher;

use Symfony\Component\PasswordHasher\Hasher\CheckPasswordLengthTrait;
use Symfony\Component\PasswordHasher\PasswordHasherInterface;

class Md5Hasher implements PasswordHasherInterface
{
    use CheckPasswordLengthTrait;

    public function hash(string $plainPassword): string
    {
        // Utilisation de bcrypt au lieu de MD5 pour la sécurité
        return password_hash($plainPassword, PASSWORD_BCRYPT, ['cost' => 12]);
    }

    public function verify(string $hashedPassword, string $plainPassword): bool
    {
        if ('' === $plainPassword) {
            return false;
        }

        // Vérification avec password_verify qui supporte bcrypt et MD5 (pour compatibilité)
        // Si le hash est en MD5 (ancien format), on vérifie avec MD5
        // Sinon, on utilise password_verify pour bcrypt
        if (strlen($hashedPassword) === 32 && ctype_xdigit($hashedPassword)) {
            // Ancien format MD5 (32 caractères hexadécimaux)
            return $hashedPassword === md5($plainPassword);
        }
        
        // Nouveau format bcrypt
        return password_verify($plainPassword, $hashedPassword);
    }

    public function needsRehash(string $hashedPassword): bool
    {
        // Si le hash est en MD5 (ancien format), il faut le rehasher
        if (strlen($hashedPassword) === 32 && ctype_xdigit($hashedPassword)) {
            return true;
        }
        
        // Vérifier si le hash bcrypt nécessite un rehash (coût trop faible)
        return password_needs_rehash($hashedPassword, PASSWORD_BCRYPT, ['cost' => 12]);
    }
}