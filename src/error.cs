using Type;

namespace ErrorHandling;

public class Result<T>
{
    public T Value { get; }
    public Error Error { get; }
    public bool IsSuccess { get; }

    private Result(T value, Error error, bool isSuccess)
    {
        Value = value;
        Error = error;
        IsSuccess = isSuccess;
    }

    public static Result<T> Success(T value) => new(value, default!, true);
    public static Result<T> Fail(Error error) => new(default!, error, false);

    public T Unwrap()
    {
        if (!IsSuccess) throw new InvalidOperationException("Tried to unwrap a failed result.");
        return Value;
    }
}

public readonly struct RVoid
{
    public static Result<RVoid> Success() => Result<RVoid>.Success(new());
    public static Result<RVoid> Fail(Error e) => Result<RVoid>.Fail(e);
}



public enum ErrorSeverity
{
    /*
    Non recoverable error, just give up restart app or method
    */
    Fatal,
    /*
    User should be able to recover somehow without having to restart the app
    */
    Recoverable
}

public abstract record Error(ErrorSeverity Severity)
{
    public abstract string ErrorMessage();

    public sealed record NFCLost(string Message, ErrorSeverity Severity = ErrorSeverity.Fatal)
        : Error(Severity)
    {
        public override string ErrorMessage() => Message;
    }

    public sealed record Parse(string Message, ErrorSeverity Severity = ErrorSeverity.Recoverable)
        : Error(Severity)
    {
        public override string ErrorMessage() => Message;
    }

    // TODO, Add recoverable/fatality
    public sealed record SwError(SwStatus Status, ErrorSeverity Severity = ErrorSeverity.Recoverable)
        : Error(Severity)
    {
        public override string ErrorMessage() => Status.Message;
    }

    public sealed record ClientErrorFormat(string Message, ErrorSeverity Severity = ErrorSeverity.Recoverable)
        : Error(Severity)
    {
        public override string ErrorMessage() => Message;
    }


    public sealed record AuthenticationToken(string Message, ErrorSeverity Severity = ErrorSeverity.Recoverable)
        : Error(Severity)
    {
        public override string ErrorMessage() => Message;
    }

    public sealed record Other(string Message, ErrorSeverity Severity = ErrorSeverity.Fatal)
       : Error(Severity)
    {
        public override string ErrorMessage() => Message;
    }
}
