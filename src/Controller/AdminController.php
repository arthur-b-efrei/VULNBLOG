<?php

namespace App\Controller;

use App\Entity\User;
use App\Repository\CommentRepository;
use App\Repository\PostRepository;
use App\Repository\UserRepository;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Security\Csrf\CsrfToken;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;

class AdminController extends AbstractController
{
    #[Route('/admin', name: 'app_admin')]
    public function index(UserRepository $userRepository): Response
    {
        return $this->render('admin/index.html.twig', [
            'users' => $userRepository->findAll(),
        ]);
    }

    #[Route('/user/role/{user}', name: 'app_admin_role', methods: ['POST'])]
    public function changeRole(
        Request $request, 
        UserRepository $userRepository, 
        User $user,
        CsrfTokenManagerInterface $csrfTokenManager
    ): Response
    {
        // Validation du token CSRF
        $token = $request->request->get('_token');
        if (!$csrfTokenManager->isTokenValid(new CsrfToken('app_admin_role', $token))) {
            $this->addFlash('error', 'Invalid security token');
            return $this->redirectToRoute('app_admin');
        }

        $user = $userRepository->find($user);
        $user->setAdmin($request->get('role') === '1');
        $userRepository->save($user, true);

        $this->addFlash('success', 'Role changed successfully');
        return $this->redirectToRoute('app_admin');
    }

    #[Route('/admin/delete/{user}', name: 'app_admin_delete')]
    public function deleteUser(
        EntityManagerInterface $entityManager,
        PostRepository         $postRepository,
        CommentRepository      $commentRepository,
        User                   $user
    ): Response
    {
        $postCount = $postRepository->countByUser($user);
        $commentCount = $commentRepository->countByUser($user);

        if ($postCount > 0 || $commentCount > 0) {
            $this->addFlash('error', 'User cannot be deleted because it has posts or comments');
        } else {
            $entityManager->remove($user);
            $entityManager->flush();
            $this->addFlash('success', 'User deleted successfully');
        }

        return $this->redirectToRoute('app_admin');
    }

    // Create a new user account
    #[Route('/admin/create', name: 'app_admin_create')]
    public function createUser(
        UserRepository $userRepository, 
        Request $request,
        CsrfTokenManagerInterface $csrfTokenManager
    ): Response
    {
        // Validation du token CSRF
        $token = $request->request->get('_token');
        if (!$csrfTokenManager->isTokenValid(new CsrfToken('app_admin_create', $token))) {
            $this->addFlash('error', 'Invalid security token');
            return $this->redirectToRoute('app_admin');
        }

        $email = $request->get('email');
        $username = $request->get('username');
        $password = $request->get('password');
        $firstname = $request->get('firstname');
        $lastname = $request->get('lastname');
        $isAdmin = $request->get('role') === '1';

        // Check if email is valid and not already in use
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $this->addFlash('error', 'Email is not valid');
            return $this->redirectToRoute('app_admin');
        }

        // Check if email is not already in use
        $user = $userRepository->findOneBy(['email' => $email]);
        if ($user) {
            $this->addFlash('error', 'Email is already in use');
            return $this->redirectToRoute('app_admin');
        }

        // Check if username is not already in use
        $user = $userRepository->findOneBy(['username' => $username]);
        if ($user) {
            $this->addFlash('error', 'Username is already in use');
            return $this->redirectToRoute('app_admin');
        }

        // Check if password is not empty
        if (empty($password)) {
            $this->addFlash('error', 'Password cannot be empty');
            return $this->redirectToRoute('app_admin');
        }

        // Create the new user
        $user = new User();
        $user->setEmail($email);
        $user->setAdmin($isAdmin);
        $user->setUsername($username);
        $user->setFirstname($firstname);
        $user->setLastname($lastname);
        $user->setPassword(password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]));

        $userRepository->save($user, true);
        $this->addFlash('success', 'User created successfully');

        return $this->redirectToRoute('app_admin');
    }
}
