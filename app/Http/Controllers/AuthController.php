<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use App\Models\User;
use Validator;


class AuthController extends Controller
{
    
     /**
     * Create a new AuthController instance.
     *
     * @return void
     */
    public function __construct() {
        $this->middleware('auth:api', ['except' => ['login', 'register', 'name']]);
    }

    /**
     * Login
     * @OA\Post (
     *     path="/auth/login",
     *     tags={"Authentication"},
     *     summary="Login with email & password",
     *     description="This login api customer can login with email & password",
     *     @OA\RequestBody(
     *         @OA\MediaType(
     *             mediaType="application/json",
     *             @OA\Schema(
     *                 @OA\Property(
     *                      type="object",
     *                      @OA\Property(
     *                          property="email",
     *                          type="string"
     *                      ),
     *                      @OA\Property(
     *                          property="password",
     *                          type="string"
     *                      )
     *                 ),
     *                 example={
     *                     "email":"mdrabiulhasan.me@gmail.com",
     *                     "password":"123456"
     *                }
     *             )
     *         )
     *      ),
     *     @OA\Response(
     *          response=200,
     *          description="Successfully Login",
     *          @OA\JsonContent(
     *              type="object",
     *              example={"status":200,"success":true,"message":"Login successfully","data":{"token":"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwOlwvXC8xMjcuMC4wLjE6ODAwMFwvYXBpXC9hdXRoXC9sb2dpbiIsImlhdCI6MTY1MzU1NDE0NiwiZXhwIjoxNjUzNTU3NzQ2LCJuYmYiOjE2NTM1NTQxNDYsImp0aSI6IlhseGpwWERmYnBrZzJQMmYiLCJzdWIiOjEsInBydiI6IjIzYmQ1Yzg5NDlmNjAwYWRiMzllNzAxYzQwMDg3MmRiN2E1OTc2ZjcifQ.763UrUujMp_n6GFC5yR1ahsdkzq_6JF53xJSv8A_e2g","token_type":"bearer","name":"Rabiul Hasan","expires_in":3600}}
     *          )
     *     ),
     *     @OA\Response(
     *          response=400,
     *          description="Email & Password Error",
     *          @OA\JsonContent(
     *              type="object",
     *              example={"status":400,"success":false,"message":"Your email or password was incorrect"}
     *          )
     *     ),
     *      @OA\Response(
     *          response=403,
     *          description="success",
     *          @OA\JsonContent(
     *              @OA\Property(property="status", type="integer", example=403),
     *              @OA\Property(property="success", type="boolean", example=false),
     *              @OA\Property(property="message", type="string", example="Unauthenticated User"),
     *          )
     *      ),
     * 
     * )
     */

    public function login(Request $request){
    	$validator = Validator::make($request->all(), [
            'email'    => 'required|email',
            'password' => 'required|string|min:6',
        ]);

        $credentials = $request->only(['email', 'password']);


        if ($token = $this->guard()->attempt($credentials)) {
            return $this->respondWithToken($token);
        }


        if (! $token = Auth::attempt($credentials)) {
            $data = [
                "status"  => 400,
                "success" => false,
                "message" => "Your email or password was incorrect"
            ];
            return response()->json($data);
        }

        // successfully login
        return $this->respondWithToken($token);
    }

    /**
     * Register
     * @OA\Post (
     *     path="/auth/register",
     *     tags={"Authentication"},
     *     summary="New Consumer Registration",
     *     description="This register api can add new consumer in our application",
     *     @OA\RequestBody(
     *         @OA\MediaType(
     *             mediaType="application/json",
     *             @OA\Schema(
     *                 @OA\Property(
     *                      type="object",
     *                      @OA\Property(
     *                          property="name",
     *                          type="string"
     *                      ),
     *                      @OA\Property(
     *                          property="email",
     *                          type="string"
     *                      ),
     *                      @OA\Property(
     *                          property="password",
     *                          type="string"
     *                      ),
     *                      @OA\Property(
     *                          property="password_confirmation",
     *                          type="string"
     *                      )
     *                 ),
     *                 example={
     *                     "name":"Rabiul Hasan",
     *                     "email":"mdrabiulhasan.me@gmail.com",
     *                     "password":"123456",
     *                     "password_confirmation":"123456"
     *                }
     *             )
     *         )
     *      ),
     *     @OA\Response(
     *          response=201,
     *          description="Successfully Register",
     *          @OA\JsonContent(
     *              type="object",
     *              example={"message":"User successfully registered","user":{"name":"Rabiul Hasan","email":"mdrabiulhasan1.me@gmail.com","updated_at":"2022-05-26T09:26:17.000000Z","created_at":"2022-05-26T09:26:17.000000Z","id":2}}
     *          )
     *     ), 
     * )
     */
    public function register(Request $request) {
        $validator = Validator::make($request->all(), [
            'name'     => 'required|string|between:2,100',
            'email'    => 'required|string|email|max:100|unique:users',
            'password' => 'required|string|confirmed|min:6',
        ]);

        if($validator->fails()){
            return response()->json($validator->errors()->toJson(), 400);
        }

        $user = User::create(array_merge(
                    $validator->validated(),
                    ['password' => bcrypt($request->password)]
                ));

        return response()->json([
            'message' => 'User successfully registered',
            'user' => $user
        ], 201);
    }


    /**
     * Log the user out (Invalidate the token).
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function logout() {
        auth()->logout();

        return response()->json(['message' => 'User successfully signed out']);
    }

    /**
     * Refresh a token.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function refresh() {
        return $this->createNewToken(auth()->refresh());
    }

    /**
     * user Profile
     * @OA\Get (
     *     path="/auth/user-profile",
     *     tags={"Authentication"},
     *     summary="Authenticated User Profile",
     *     description="This api fetch authentication user profile",
     *     security={{"jwt_token":{}}},
     *     @OA\Response(
     *          response=201,
     *          description="Success",
     *          @OA\JsonContent(
     *              type="object",
     *              example={"id":1,"name":"Rabiul Hasan","email":"mdrabiulhasan.me@gmail.com","email_verified_at":null,"created_at":"2022-05-26T03:49:08.000000Z","updated_at":"2022-05-26T03:49:08.000000Z"}
     *          )
     *     ), 
     * )
     */
    public function userProfile() {
        return response()->json(auth()->user());
    }

    /**
     * Get the token array structure.
     *
     * @param  string $token
     *
     * @return \Illuminate\Http\JsonResponse
     */
    protected function createNewToken($token){
        return response()->json([
            'access_token' => $token,
            'token_type'   => 'bearer',
            'expires_in'   => 3600,
            'user'         => auth()->user()
        ]);
    }




    /**
     * Get the token array structure.
     *
     * @param  string $token
     *
     * @return \Illuminate\Http\JsonResponse
     */
    protected function respondWithToken($token)
    {
        $data = [
            "status" => 200,
            "success" => true,
            "message" => "Login successfully",
            "data" => [
                'token'      => $token,
                'token_type' => 'bearer',
                'name'       => $this->guard()->user()->name,
                'expires_in' => auth('api')->factory()->getTTL() * 60
            ]
        ];
        return response()->json($data);
    }

     /**
     * Get the guard to be used during api-authentication.
     *
     * @return \Illuminate\Contracts\Auth\Guard
     */
    public function guard()
    {
        return Auth::guard('api');
    }



    /**
     * Url Parameter
     * @OA\Get (
     *     path="/auth/name/{name}",
     *     tags={"Authentication"},
     *     summary="Url Parameter Pass",
     *     description="This api fetch url parameter pass",
     *      @OA\Parameter(
     *         in="path",
     *         name="name",
     *         required=true,
     *         @OA\Schema(type="string")
     *     ),
     *     @OA\Response(
     *          response=201,
     *          description="Success",
     *          @OA\JsonContent(
     *              type="object",
     *              example={"status":200,"success":true,"message":"Your name is Rabiul-Hasan"}
     *          )
     *     ), 
     * )
     */
    public function name($name){
        $data = [
            "status"  => 200,
            "success" => true,
            "message" => "Your name is {$name}"
        ];
        return response()->json($data);
    }

}
