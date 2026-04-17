package br.ufsc.labsec.pbad.selectionchallengepsc.exceptions;

public class InvalidRequestException extends RuntimeException {
    public InvalidRequestException(String message) {
        super(message);
    }
}
