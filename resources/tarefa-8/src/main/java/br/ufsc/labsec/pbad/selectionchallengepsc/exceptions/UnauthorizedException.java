package br.ufsc.labsec.pbad.selectionchallengepsc.exceptions;

public class UnauthorizedException extends RuntimeException {
    public UnauthorizedException(String message) {
        super(message);
    }
}
