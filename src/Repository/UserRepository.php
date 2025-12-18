<?php

namespace App\Repository;

use App\Entity\User;
use Doctrine\Bundle\DoctrineBundle\Repository\ServiceEntityRepository;
use Doctrine\Persistence\ManagerRegistry;
use Symfony\Component\Security\Core\Exception\UnsupportedUserException;
use Symfony\Component\Security\Core\User\PasswordAuthenticatedUserInterface;
use Symfony\Component\Security\Core\User\PasswordUpgraderInterface;
use function PHPUnit\Framework\returnArgument;

/**
 * @extends ServiceEntityRepository<User>
 *
 * @method User|null find($id, $lockMode = null, $lockVersion = null)
 * @method User|null findOneBy(array $criteria, array $orderBy = null)
 * @method User[]    findAll()
 * @method User[]    findBy(array $criteria, array $orderBy = null, $limit = null, $offset = null)
 */
class UserRepository extends ServiceEntityRepository implements PasswordUpgraderInterface
{
    public function __construct(ManagerRegistry $registry)
    {
        parent::__construct($registry, User::class);
    }

    public function save(User $entity, bool $flush = false): void
    {
        $this->getEntityManager()->persist($entity);

        if ($flush) {
            $this->getEntityManager()->flush();
        }
    }

    public function remove(User $entity, bool $flush = false): void
    {
        $this->getEntityManager()->remove($entity);

        if ($flush) {
            $this->getEntityManager()->flush();
        }
    }

    public function total(): int
    {
        return $this->createQueryBuilder("u")
            ->select("COUNT(u.id)")
            ->getQuery()
            ->getSingleScalarResult();
    }

    /**
     * Used to upgrade (rehash) the user's password automatically over time.
     */
    public function upgradePassword(PasswordAuthenticatedUserInterface $user, string $newHashedPassword): void
    {
        if (!$user instanceof User) {
            throw new UnsupportedUserException(sprintf('Instances of "%s" are not supported.', \get_class($user)));
        }

        $user->setPassword($newHashedPassword);

        $this->save($user, true);
    }

    /**
     * @return array|false
     */
    public function getUserLogin(string $email, string $password)
    {
        // Trouver l'utilisateur par email uniquement (sécurisé avec Doctrine)
        $user = $this->findOneBy(['email' => $email]);
        
        if (!$user instanceof User) {
            return false;
        }
        
        $storedPassword = $user->getPassword();
        
        // Vérifier le mot de passe : supporte MD5 (ancien format) et bcrypt (nouveau format)
        $passwordValid = false;
        
        // Si le hash est en MD5 (32 caractères hexadécimaux), vérifier avec MD5 pour compatibilité
        if (strlen($storedPassword) === 32 && ctype_xdigit($storedPassword)) {
            $passwordValid = ($storedPassword === md5($password));
        } else {
            // Sinon, utiliser password_verify pour bcrypt
            $passwordValid = password_verify($password, $storedPassword);
        }
        
        if (!$passwordValid) {
            return false;
        }
        
        // Si le mot de passe est en MD5, le rehasher en bcrypt pour la prochaine fois
        if (strlen($storedPassword) === 32 && ctype_xdigit($storedPassword)) {
            $user->setPassword(password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]));
            $this->save($user, true);
        }
        
        return [
            'id' => $user->getId(),
            'email' => $user->getEmail(),
            'password' => $user->getPassword(),
            'username' => $user->getUsername(),
            'firstname' => $user->getFirstname(),
            'lastname' => $user->getLastname(),
            'aboutMe' => $user->getAboutMe(),
            'avatar' => $user->getAvatar(),
            'isAdmin' => $user->isAdmin(),
        ];
    }
}
