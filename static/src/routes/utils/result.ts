export class Result<T> {
    readonly success: boolean;
    readonly errormsg: string;
    readonly data: T | null;

    // 默认只需要传入 data， 即成功
    private constructor(
        data: T | null,
        success: boolean = true,
        errormsg: string = "",
    ) {
        this.success = success;
        this.errormsg = errormsg;
        this.data = data;
    }

    // 方法
    isSuccess(): boolean {
        return this.success;
    }

    getData(): T | null {
        return this.data;
    }

    errorMsg(): string {
        return this.errormsg;
    }

    // 静态方法，创建 Result 类型对象
    static Ok<T>(data: T): Result<T> {
        return new Result(data);
    }

    static Fail<T>(msg: string): Result<T> {
        return new Result<T>(null, false, msg);
    }
}
