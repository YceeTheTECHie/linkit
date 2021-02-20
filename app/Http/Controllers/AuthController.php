<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Models\User;
use Validate;
use Illuminate\Suppport\Facades\Auth;
class AuthController extends Controller
{
    public function register(Request $request) 
    {
        $validatedData = $request->validate([
            'name' => 'required|max:55',
            'email' => 'email|required|unique:users',
            'password' => 'required'
        ]);
        
        $validatedData['password'] = bcrypt($request->password);
        try {   
                $user = User::create($validatedData);
                $accessToken = $user->createToken('auth-token')->accessToken;
                if ($accessToken) return response()->json([ 'user' => $user, 'access-token' => $accessToken]);
        }
        catch(Exception $error){
            return response()->json($error);
        }


    }

    public function login(Request $request)
    {
        $loginData = $request->validate([
            'email' => 'email|required',
            'password' => 'required'
        ]);    
        if (!auth()->attempt($loginData)) return response()->json(['message'=> 'invalid credentials']);
        
        $accessToken = auth()->user()->createToken('authToken')->accessToken;
        return response(['user' => auth()->user(), 'access_token' => $accessToken]);
    //
    }
}