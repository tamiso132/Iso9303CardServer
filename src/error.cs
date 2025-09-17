public class Result<T, E>
{
    public T Value { get; }
    public E Error { get; }
    public bool IsSuccess { get; }

    private Result(T value, E error, bool isSuccess)
    {
        Value = value;
        Error = error;
        IsSuccess = isSuccess;
    }

    public static Result<T, E> Success(T value) => new(value, default!, true);
    public static Result<T, E> Fail(E error) => new(default!, error, false);

    public T Unwrap()
    {
        return Value;
    }
}
