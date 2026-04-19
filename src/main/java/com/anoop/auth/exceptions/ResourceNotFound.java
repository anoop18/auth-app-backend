package com.anoop.auth.exceptions;

public class ResourceNotFound extends RuntimeException {
    public ResourceNotFound(String message) {
        super(message);
    }
    public ResourceNotFound() {
     super("Resource  not found !!");
    }
}
