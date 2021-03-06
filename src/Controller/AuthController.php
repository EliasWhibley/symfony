<?php

/**
 * Created by PhpStorm.
 * User: hicham benkachoud
 * Date: 06/01/2020
 * Time: 20:39
 */

namespace App\Controller;


use App\Entity\User;
use App\Entity\Users;
use Exception;
use Lexik\Bundle\JWTAuthenticationBundle\Services\JWTTokenManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Security\Core\Encoder\UserPasswordEncoderInterface;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Serializer\Encoder\JsonEncoder;
use Symfony\Component\Serializer\Encoder\XmlEncoder;
use Symfony\Component\Serializer\Normalizer\ObjectNormalizer;
use Symfony\Component\Serializer\Serializer;

class AuthController extends ApiController
{

    public function register(Request $request, UserPasswordEncoderInterface $encoder)
    {
        $em = $this->getDoctrine()->getManager();
        $request = $this->transformJsonBody($request);
        $username = $request->get('username');
        $password = $request->get('password');
        $email = $request->get('email');

        if (empty($username) || empty($password) || empty($email)) {
            return $this->respondValidationError("Invalid Username or Password or Email");
        }


        $user = new Users($username);
        $user->setPassword($encoder->encodePassword($user, $password));
        $user->setEmail($email);
        $user->setIsValid(false);
        $user->setUsername($username);
        $em->persist($user);
        $em->flush();
        return $this->respondWithSuccess(sprintf('User %s successfully created', $user->getUsername()));
    }

    /**
     * @param UserInterface $user
     * @param JWTTokenManagerInterface $JWTManager
     * @return JsonResponse
     */
    public function getTokenUser(Request $request, JWTTokenManagerInterface $JWTManager, UserPasswordEncoderInterface $encoder)
    {


        $em = $this->getDoctrine()->getRepository(Users::class);



        $content = $request->getContent();
        $json = json_decode($content, true);
        $usernameSended = $json["username"];
        $findUser = $em->findOneBy([
            "username" => $usernameSended
        ]);
        $passSended = $json["password"];


        $validPassword = $encoder->isPasswordValid(
            $findUser, // the encoded password
            $passSended,       // the submitted password

        );
        $serializer = $this->get('serializer');
        $data = $serializer->serialize($findUser, 'json');

        if (!$validPassword) {
            return new Exception();
        } else {
            return new JsonResponse(['token' => $JWTManager->create($findUser)]);
        }
    }
}
